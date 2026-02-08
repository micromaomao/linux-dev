# Landlock mutable domains

This patchset introduces the concept of "supervisor" and "supervisee" rulesets, which are Landlock rulesets that are joined together when enforced.  The supervisee ruleset can be thought of as the "static" part of a domain, and the (optional) supervisor ruleset can be thought of as the "dynamic" part.  The two rulesets can have different rules and access rights for individual rules, but they internally have the same sets of handled access and scope bits.  When an access request is evaluated for processes in such domains, the access is allowed if, for each layer, either the supervisee or the supervisor ruleset of that domain allows the access.

A Landlock supervisor will first create the supervisor ruleset, which internally creates a ref-counted landlock_supervisor which the unmerged (and in fact, unmergeable) landlock_ruleset will point to.  Through a new ioctl, the user can get a supervisee ruleset with the attached supervisor (this relationship is not necessarily 1-1), which can then be passed to landlock_restrict_self() by a child process.  The supervisor can also at any time (before the ioctl, before the landlock_restrict_self() call, or after it) modify the supervisor ruleset to add or remove rules or change access rights, and commit those changes through a flag passed to landlock_add_rule(), after which the changes start affecting the child.

The supervisee ruleset is immutable, and internally we continue to "fold" rules from parents into the child's rbtree.  Since all ancestor supervisor rulesets are mutable, we cannot simply fold the supervisor rules from parents into its children at enforce time, as it may be removed or changed later at a parent layer.  Therefore, if an access is not allowed by any layer's supervisee ruleset (which is quick to check thanks to the folding of the supervisee ruleset from parent to child), Landlock will then have to check that the access is allowed by the supervisor rulesets of all the denying layers. (The access is also denied if any of the denying layers does not have a supervisor ruleset.)

To enable removing rules from a ruleset, we also implement the LANDLOCK_ADD_RULE_INTERSECT flag for landlock_add_rule().  If this is passed, instead of adding rules, the corresponding existing rule, if it exists, is updated to be the intersection of the existing access rights and the specified access rights.  If the result is zero, the rule is removed.

(For consistency, the LANDLOCK_ADD_RULE_INTERSECT flag will be supported for both supervisor and supervisee (i.e. existing) rulesets, but it is probably only useful for supervisor rulesets.)

There is future work planned to implement a notification and waiting mechanism to allow the supervisor to be asked for a decision when a denied (and not quieted) access happens, but that is out of the scope of this patchset.

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

During access checks, the supervisee ruleset is checked first; if denied, `landlock_check_supervisor_access()` consults the supervisor's committed ruleset via RCU for each denying layer.  For optional access rights (TRUNCATE, IOCTL_DEV), which are recorded at `open()` time, the supervisor is re-checked at operation time via `landlock_check_supervisor_optional_access()` to allow dynamically-added rules to take effect on already-opened files.  This enables a future notification workflow where the supervisor can add rules in response to access attempts (notifications are not yet implemented).

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
