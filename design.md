# Landlock mutable domains

This patchset introduces the concept of "supervisor" and "supervisee" rulesets, which are Landlock rulesets that are joined together when enforced.  The supervisee ruleset can be thought of as the "static" part of a domain, and the (optional) supervisor ruleset can be thought of as the "dynamic" part.  The two rulesets can have different rules and access rights for individual rules, but they internally have the same sets of handled access and scope bits.  When an access request is evaluated for processes in such domains, the access is allowed if, for each layer, either the supervisee or the supervisor ruleset of that domain allows the access.

A Landlock supervisor will first create the supervisor ruleset, which internally creates a ref-counted landlock_supervisor which the unmerged (and in fact, unmergeable) landlock_ruleset will point to.  Through a new ioctl, the user can get a supervisee ruleset with the attached supervisor (this relationship is not necessarily 1-1), which can then be passed to landlock_restrict_self() by a child process.  The supervisor can also at any time (before the ioctl, before the landlock_restrict_self() call, or after it) modify the supervisor ruleset to add or remove rules or change access rights, and commit those changes through a flag passed to landlock_add_rule(), after which the changes start affecting the child.

The supervisee ruleset is immutable, and internally we continue to "fold" rules from parents into the child's rbtree.  Since all ancestor supervisor rulesets are mutable, we cannot simply fold the supervisor rules from parents into its children at enforce time, as it may be removed or changed later at a parent layer.  Therefore, if an access is not allowed by any layer's supervisee ruleset (which is quick to check thanks to the folding of the supervisee ruleset from parent to child), Landlock will then have to check that the access is allowed by the supervisor rulesets of all the denying layers. (The access is also denied if any of the denying layers does not have a supervisor ruleset.)

To enable removing rules from a ruleset, we also implement the LANDLOCK_ADD_RULE_INTERSECT flag for landlock_add_rule().  If this is passed, instead of adding rules, the corresponding existing rule, if it exists, is updated to be the intersection of the existing access rights and the specified access rights.  If the result is zero, the rule is removed.

(For consistency, the LANDLOCK_ADD_RULE_INTERSECT flag will be supported for both supervisor and supervisee (i.e. existing) rulesets, but it is probably only useful for supervisor rulesets.)

Additionally, a supervisor notification mechanism is implemented that allows the supervisor to be notified when an access is denied by its supervised layer.  This is described in the "Supervisor Notification" section below.

## uAPI example

```c
/*
 * This landlock_ruleset_attr controls the handled/quiet/scope bits for
 * this layer (internally shared by both the supervisor and supervisee
 * rulesets).
 */
struct landlock_ruleset_attr attr = {
    .handled_access_fs = ...,
    .handled_access_net = ...,
    .scoped = ...,
    .quiet_access_fs = ...,
    .quiet_access_net = ...,
    .quiet_scoped = ...,
};

/* supervisor_fd should default to CLOEXEC */
int supervisor_fd = landlock_create_ruleset(&attr, sizeof(attr), LANDLOCK_CREATE_SUPERVISOR);
if (supervisor_fd < 0) {
    perror("landlock_create_ruleset");
}
/*
 * supervisor_fd can then be passed to landlock_add_rule, but it does not
 * work with landlock_restrict_self.  Not working for restrict_self means
 * that if a sandboxer accidentally passes the supervisor fd to the child,
 * it would not work in the same way as the supervisee fd, and therefore
 * the error is more discoverable.
 */
 if (landlock_add_rule(supervisor_fd, ...) < 0) {
    perror("landlock_add_rule");
 }
 /* ... */
 /*
  * Any changes to the supervisor ruleset must be committed, even before
  * any child calls landlock_restrict_self().  Without committing, the
  * supervisor ruleset still behaves as if it is empty.
  */
 if (landlock_add_rule(supervisor_fd, ..., ..., LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR) < 0) {
    perror("landlock_add_rule(COMMIT)");
}

/* Creates the supervisee ruleset */
int supervisee_fd = ioctl(supervisor_fd, LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET, /* flags= */ 0);
if (supervisee_fd < 0) {
    perror("ioctl(LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET)");
}

/*
 * Initial supervisor ruleset rules can be populated here via
 * landlock_add_rule().
 */

pid_t child = fork();
if (child == 0) {
    /*
     * The supervisor should not leak supervisor_fd to any untrusted code,
     * but Landlock will protect against usage by the supervisee even if
     * this is leaked.
     */
    close(supervisor_fd);
    if (landlock_restrict_self(supervisee_fd, 0) < 0) {
        perror("landlock_restrict_self");
    }
    execve(...);
    perror("execve");
} else {
    close(supervisee_fd);
    /* Here, the supervisor can add rules via landlock_add_rule() */
    /* ... */
    /* Or remove rules via landlock_add_rule() with LANDLOCK_ADD_RULE_INTERSECT */
    /*
     * Added rules doesn't come into effect until a final
     * landlock_add_rule() with commit flag (which may also just add a
     * dummy rule with access=0):
     */
    if (landlock_add_rule(supervisor_fd, ..., ..., LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR) < 0) {
        perror("landlock_add_rule(COMMIT)");
    }
    /*
     * The above landlock_add_rule() will check that the current task is
     * not under (either directly or as a descendant) a Landlock domain
     * with the passed in supervisor ruleset.
     */
}
```

## FAQ:

1. Why require a commit operation?

   This is probably not a necessary requirement with an rbtree based implementation - it can be made thread-safe with RCU while still allowing lockless access checks without too much overhead.  However, there is a possibility that the domain lookup might become a hashtable with some future enhancement, at which point it would be better to have an explicit commit operation to avoid rebuilding the hashtable for every landlock_add_rule().

## Implementation notes

In order to store additional data and locks for the supervisor, we create a new `struct landlock_supervisor`.

Since struct landlock_hierarchy already neatly maps to layers, for this implementation we add a `struct landlock_supervisor` pointer for each layer to their corresponding `struct landlock_hierarchy`.  A future revision may optimize on this to reduce pointer chasing, depending on benchmark outcome.  There is also a `struct landlock_supervisor` pointer in the `struct landlock_ruleset`, used only for unmerged rulesets - for the supervisee ruleset this points to the attached landlock_supervisor, on landlock_restrict_self() this is copied to the landlock_hierarchy, and for the supervisor ruleset this is simply the corresponding supervisor struct.  Since we can only return ruleset fds from landlock_create_ruleset, the user-space API does not directly expose a `struct landlock_supervisor` handle, but rather, the supervisor is accessed through the supervisor ruleset's supervisor field.

One of the main tricky areas of this work is the implementation of LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR.  We want two features:
- atomic commit (the supervised program should not "experience" any rule changes until they are committed, and once it is committed it should see all the changes together)
- lockless access checks (even when the supervisee ruleset does not allow the access, necessitating checking the supervisor rulesets, this should still not involve any locks)

In order to achieve atomic commit, the supervisor fd cannot actually point to (and thus allow editing) the "live" ruleset.  Instead, when a LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR is requested, a new struct landlock_ruleset is created, the rules are copied over from the existing supervisor ruleset, and the pointer in the landlock_supervisor is swapped.  This process holds both the lock on the "user-accessible" ruleset and the lock on the `struct landlock_supervisor`.

Currently access checks do not take any locks, since the rulesets are immutable, and we want to keep this lockless property.  In order to do this, the live ruleset pointer needs to be RCU-protected, and the freeing of the previously live ruleset needs to be RCU synchronized.  To reduce complexity, this initial implementation uses synchronize_rcu() directly in the calling thread of LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR, and frees the old supervisor ruleset afterwards, but this can be rewritten to use call_rcu() in a future iteration if necessary (which will allow quicker commits).

During access checks, for each step of the path walk, after landlock_unmask_layers()-ing the supervisee rule, if the access is not already allowed, we check for rules in the supervisor ruleset and call landlock_unmask_layers() on them too.

To ensure atomicity of access checks with respect to supervisor commits, we pre-capture the supervisor committed ruleset pointers at the start of the path walk (in `is_access_to_paths_allowed`).  Without this, a race condition could occur:

1. Initially, supervisee ruleset allows access to /a/
2. An access check for /a/b starts, finds no rules on /a/b, then gets preempted
3. Supervisor removes the /a rule and adds a rule for /a/b in one commit
4. The original access check resumes, finds no rules on /a either (seeing the new commit), and incorrectly denies access

By capturing the committed rulesets into a `struct supervisor_committed_cache` (16 pointers, 128 bytes on 64-bit) at the start, the entire path walk uses a consistent snapshot.  This stack space cost is the tradeoff for atomicity.

An alternative approach would be to perform a separate path walk for supervisor rules only if the supervisee walk denies access, but this has drawbacks:

- Path walk is significantly slower than chasing some pointers and doing some extra rb tree searches to check supervisor rules, so this is less efficient.  It will be even less efficient once we switch to a hash table based ruleset implementation, which will reduce the overhead of checking supervisor rules even further.
- The two path walks can end up walking different paths if a rename happens in the middle.
- The refer domain check logic would need to be repeated and thus become more complex.

For optional access rights (TRUNCATE, IOCTL_DEV), which are recorded at `open()` time, the supervisor is re-checked at operation time via `check_supervisor_optional_access_recheck()`.  This function reuses `is_access_to_paths_allowed()` to perform a full path walk, ensuring that supervisor rules on parent directories apply to child files.  The re-check also computes updated `deny_masks` and `quiet_optional_accesses` for proper audit logging.  This enables a future notification workflow where the supervisor can add rules in response to access attempts (notifications are not yet implemented).

Here is a diagram of the relevant structures and relationships:

```
  * landlock_create_ruleset(..., LANDLOCK_CREATE_SUPERVISOR);
    |
    +-> fd1: [landlock-ruleset] -+
                                 |
        +------------------------v+
        |struct landlock_ruleset  |
        |                         |
      +-+- supervisor             |
      | |  ...                    |
      | +-------------------------+
      |  ^ This is the unmerged (and unmergeable) ruleset
      |    the supervisor holds a reference to.
      |
      | +-----------------------------+
+-----+->struct landlock_supervisor   <---------------------------------------------------+
|       |                             |                                                   |
|     +-+- committed_ruleset          |                                                   |
|     | |- lock                       |                                                   |
|     | |- usage                      |                                                   |
|     | |  ...                        |                                                   |
| RCU | +-----------------------------+                                                   |
|     |                                                                                   |
|     | +------------------------+                                                        |
|     +->struct landlock_ruleset |                                                        |
|       |                        |                                                        |
|       |- supervisor = NULL     |                                                        |
|       |  ...                   |                                                        |
|       +------------------------+                                                        |
|       ^ This "hidden" ruleset contains the "live" supervisor rules.                     |
|         It won't be modified again (so reads to it can be lock-free).                   |
|         On a future commit it is replaced by a new copy.                                |
|                                                                                         |
| * ioctl(fd, LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET, ...);                                |
|   |                                                                                     |
|   +-> fd2: [landlock-ruleset] -+                                                        |
|                                |                                                        |
|       +------------------------v+                                                       |
|       |struct landlock_ruleset  |                                                       |
|       |                         |                                                       |
+-------+- supervisor             |                                                       |
        |  ...                    |                                                       |
        +-------------------------+                                                       |
        ^ This is the unmerged supervisee ruleset which can later be                      |
          passed to landlock_restrict_self().                                             |
                                                                                          |
  * landlock_restrict_self(fd2, ...);                                                     |
    +------------------------+ +-------------------------+  +---------------------------+ |
    |landlock_cred_security -+->struct landlock_ruleset  |+->struct landlock_hierarchy  | |
    +------------------------+ |                         || |                           | |
                               |- supervisor = NULL      || |- parent -> ...            | |
                               |- hierarchy -------------++ |- supervisor --------------+-+
                               |  ...                    |  |  ...                      |
                               +-------------------------+  +---------------------------+
                               ^ The domain ruleset for a
                                 supervisor-controlled process.
```

## Using supervisor_sandboxer

The `samples/landlock/supervisor_sandboxer.c` sample demonstrates a file-based supervisor that reads rules from a configuration file and dynamically reloads them when the file changes.

### Configuration File Format

Each line specifies an access type and path:
```
ro /path/to/readonly/dir
rw /path/to/readwrite/dir
```

- `ro` grants read and execute access
- `rw` grants full filesystem access

### Example Usage

```bash
# Create a configuration file
$ cat > /tmp/sandbox.conf << EOF
ro /usr
ro /lib
rw /tmp
EOF

# Run a shell under the supervisor
$ ./supervisor_sandboxer /tmp/sandbox.conf /bin/sh
Loaded 3 rules from /tmp/sandbox.conf
Supervisor committed initial rules
Child process started with PID 12345

# In another terminal, modify the config to allow /home access
$ echo "ro /home" >> /tmp/sandbox.conf

# The supervisor detects the change and reloads
Config file changed, reloading rules...
Loaded 4 rules from /tmp/sandbox.conf
Supervisor committed updated rules

# Now the sandboxed process can access /home
```

The supervisor monitors the configuration file using inotify and atomically commits new rules when changes are detected, demonstrating the dynamic rule update capability.


## To consider

What if a supervisor wants to clear all rules and reconstruct the supervisor ruleset from scratch?  Forcing it to keep track of all the existing rules and use LANDLOCK_ADD_RULE_INTERSECT to remove them one by one is not ideal.

Intersect or replace?  How about just having a "clear all rules in a ruleset"?

## Supervisor Notification

The supervisor notification mechanism allows a supervisor to receive events when a supervised process is denied access.  This enables interactive decision-making: the supervisor can be told about denied accesses and decide whether to allow them (by updating rules via the mutable domain mechanism) or deny them outright.

### Design Overview

When a supervisor creates its ruleset with the `LANDLOCK_CREATE_SUPERVISOR_NOTIFICATION` flag (in addition to `LANDLOCK_CREATE_RULESET_SUPERVISOR`), the resulting supervisor has notification enabled.  The supervisor reads events from and writes responses to the supervisor ruleset fd directly, using `read()`, `write()`, and `poll()`.

The event flow for a denied access in a supervised layer with notification enabled:

1. A supervised process attempts an access that is denied by its supervisee ruleset and not allowed by the supervisor's committed ruleset either.
2. For each denying layer (walking from youngest/last to oldest/first):
   - If the layer's quiet flag is set for this access (via `LANDLOCK_ADD_RULE_QUIET`), the access is denied immediately without notification.
   - If the layer's supervisor does not have notification enabled, the access is denied immediately (with audit logging).
3. If all denying layers have notification-enabled supervisors, an event is queued to the youngest denying layer's supervisor.
4. The LSM hook returns `-ERESTARTNOINTR`, causing the syscall to restart after the supervisor responds.

To avoid DoS issues from blocking inside LSM hooks while holding inode locks, the notification mechanism uses `-ERESTARTNOINTR` combined with a task_work callback.  The hook does not block; instead:
1. The event is queued to the supervisor's event queue.
2. The hook returns `-ERESTARTNOINTR` to restart the syscall.
3. A task_work (executed before returning to user space) waits for the supervisor to make a decision.
4. If the supervisor allows the request, it should update the domain's rules accordingly (via the mutable domain mechanism).  The syscall then restarts and the updated rules should allow the access.
5. If the supervisor denies the request, the task_work sets a flag and the restarted syscall returns `-EPERM`.

Only one supervisor is notified at a time.  If multiple layers deny access, the youngest (most recently added) layer's supervisor is notified first.  If it allows access (by updating rules), the next restart of the syscall will check remaining denying layers.

### uAPI

The notification interface reuses the supervisor ruleset file descriptor.  The following operations are supported:

- **`read(supervisor_fd, buf, size)`**: Reads the next pending event from the event queue.  Returns a `struct landlock_supervise_event` containing the event type, access request, accessor PID, and (for FS events) O_PATH file descriptors for the target paths, or (for NET events) port number.  For file creation events, the fd points to the parent directory and the `destname` field contains the new filename.  Blocks if no events are pending (unless `O_NONBLOCK`).  The caller must close any received file descriptors.

- **`write(supervisor_fd, buf, size)`**: Writes one or more `struct landlock_supervise_response` to respond to previously read events.  Multiple responses can be written in a single write call.  Each response contains the event's cookie and a decision (`LANDLOCK_SUPERVISE_DECISION_ALLOW` or `LANDLOCK_SUPERVISE_DECISION_DENY`).

- **`poll(supervisor_fd, ...)`**: Returns `POLLIN` when events are pending.

Event types:
- `LANDLOCK_SUPERVISE_EVENT_TYPE_FS_ACCESS` (1): Filesystem access denial.
- `LANDLOCK_SUPERVISE_EVENT_TYPE_NET_ACCESS` (2): Network access denial.

### Interaction with Quiet Flag

The quiet flag (set via `LANDLOCK_ADD_RULE_QUIET` on rules where `quiet_access_*` is set in the ruleset attributes) serves a dual purpose:
1. It suppresses audit log entries for denied accesses (its original purpose).
2. It prevents supervisor notifications for denied accesses on objects marked quiet.

This allows a supervisor to selectively suppress notifications for known-denied paths (e.g., `/proc`) where denials are expected and should not trigger interactive decisions.

### Implementation Notes

- The `struct landlock_supervisor` is extended with notification state: an event queue, a notified events list, a spinlock, a wait queue for polling, and a `notification_enabled` flag.
- Events are represented by `struct landlock_supervise_event_kernel` which holds references to paths and PIDs.
- The notification check logic is implemented in helper functions (`landlock_check_notify_fs` in fs.c and `landlock_check_notify_net` in net.c) that iterate denying layers and queue events.
- Scope-related denials and mount operations do not trigger notifications.
- When the last reference to a supervisor is dropped (all supervised domains and the supervisor fd are closed), any pending events are automatically denied.

### supervisor_sandboxer Example

The `samples/landlock/supervisor_sandboxer.c` sample has been extended to demonstrate the notification mechanism:
- Creates the supervisor with `LANDLOCK_CREATE_SUPERVISOR_NOTIFICATION`.
- Uses `poll()` to monitor both the config file (inotify) and the supervisor fd for events.
- When a notification event is received, prints a message like "Supervisor: read access to /path denied".
- Denies all notification requests outright (the supervisor could also allow them by updating rules and responding with ALLOW).
- Supports a `quiet` config line (e.g., `quiet /tmp`) that sets the quiet flag on a path, suppressing notifications for that path.  Removing the quiet line from the config removes the quiet flag.

## Future work

Implement hash table or not?
