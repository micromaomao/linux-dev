Hi,

Recently I have been continuing work on the previously proposed Landlock
supervise feature (context below).  While I do have some rough PoCs (code
changes [1] for mutable domains and [2] for supervisor notification,
scrappy demo video [3]), because of the amount of work involved, I would
like to get some early feedback on the design before continuing.

While I would be glad to receive reviews from anyone, Günther, if you are
not too busy, can you kindly give this a review? A lot of this has already
been discussed with Mickaël, in fact a large part of this design was from
his suggestions.


[1]: https://github.com/micromaomao/linux-dev/pull/26/changes
[2]: https://github.com/micromaomao/linux-dev/pull/27/changes
[3]: https://fileshare.maowtm.org/landlock-20260214/demo.mp4

Background
----------

A while ago I sent a "Landlock supervise" RFC patch series [4], in which I
proposed to extend Landlock with additional functionality to support
"interactive" rule enforcement.  In discussion with Mickaël, we decided to
split this work into 3 stages:  quiet flag, mutable domains, and finally
supervisor notification.  Relevant discussions are at [5] and in replies
to [4].

The patch for quiet flag [6] has gone through multiple review iterations
already.  It is useful on its own, but it was also motivated by the
eventual use in controlling supervisor notification.

The next stage is to introduce "mutable domains".  The motivation for this
is two fold:

1. This allows the supervisor to allow access to (large) file hierarchies
   without needing to be woken up again for each access.
2. Because we cannot block within security_path_mknod and other
   directory-modification related hooks [7], the proposal was to return
   immediately from those hooks after queuing the supervisor notification,
   then wait in a separate task_work.  This however means that we cannot
   directly "allow" access (and even if we can, it may introduce TOCTOU
   problems).  In order to allow access to requested files, the supervisor
   has to add additional rules to the (now mutable) domain which will
   allow the required access.


[4]: https://lore.kernel.org/all/cover.1741047969.git.m@maowtm.org/
[5]: https://github.com/landlock-lsm/linux/issues/44
[6]: https://lore.kernel.org/all/cover.1766330134.git.m@maowtm.org/
[7]: https://lore.kernel.org/all/20250311.Ti7bi9ahshuu@digikod.net/


Proposed changes
----------------

This patchset introduces the concept of "supervisor" and "supervisee"
rulesets (alternative names for this are "static"/"dynamic",
"mutable"/"immutable" etc), which are Landlock rulesets that are joined
together when enforced.  The supervisee ruleset can be thought of as the
"static" part of a domain, and the supervisor ruleset can be thought of as
the "dynamic" part.  The two rulesets can have different rules and access
rights for individual rules, but they internally have the same sets of
handled access and scope bits.  When an access request is evaluated for
processes in such domains, the access is allowed if, for each layer,
either the supervisee or the supervisor ruleset of that domain allows the
access.

A Landlock supervisor will first create the supervisor ruleset, which
internally creates a ref-counted landlock_supervisor which the unmerged
(and in fact, unmergeable, to prevent accidental misuse) landlock_ruleset
will point to.  Through a new ioctl, the user can get a supervisee ruleset
with the attached supervisor (this relationship does not necessarily has
to be 1-1), which can then be passed to landlock_restrict_self() by a
child process.  The supervisor can also at any time (before the ioctl,
before the landlock_restrict_self() call, or after it) modify the
supervisor ruleset to add or remove (via a new "intersect" flag) rules or
change access rights, and commit those changes through a flag passed to
landlock_add_rule(), after which the changes start affecting the child.

The supervisee ruleset is immutable, it is basically the current
landlock_ruleset, and internally we continue to "fold" rules from parents
into the child's rbtree.  However, since all ancestor supervisor rulesets
are mutable, we cannot simply fold the supervisor rules from parents into
its children at enforce time, as it may be removed or changed later at a
parent layer.  Therefore, if an access is not allowed by any layer's
supervisee ruleset (which is quick to check thanks to the "folding" of the
supervisee rules), Landlock will then have to check that the access is
allowed by the supervisor rulesets of all the denying layers. (The access
is also denied if any of the denying layers does not have a supervisor
ruleset, in this case we don't even have to check the other supervisor
rulesets.)

To enable removing rules from a ruleset, we also implement the
LANDLOCK_ADD_RULE_INTERSECT flag for landlock_add_rule().  If this is
passed, instead of adding rules, the corresponding rule, if it exists, is
updated to be the intersection of the existing access rights and the
specified access rights.  If the result is zero, the rule is removed.  For
API consistency, the LANDLOCK_ADD_RULE_INTERSECT flag will be supported
for both supervisor and supervisee (i.e. existing) rulesets, but it is
probably only useful for supervisor rulesets.

(I'm not very certain about this intersect flag - see below for
alternative designs)

Later on, a supervisor notification mechanism can be implemented to allow
the supervisor to be notified when an access is denied by its supervised
layer, but this is not in scope for the "mutable domains" feature on its
own (although it does make it significantly more useful).


uAPI example
------------

```c
/*
 * This landlock_ruleset_attr controls the handled/quiet/scope bits for
 * this layer (internally shared by both the supervisor and supervisee
 * rulesets).
 */
struct landlock_ruleset_attr attr = {
    .handled_access_fs = ...,
    /* ... */
};

/* supervisor_fd default to CLOEXEC */
int supervisor_fd = landlock_create_ruleset(
    &attr, sizeof(attr), LANDLOCK_CREATE_SUPERVISOR);
if (supervisor_fd < 0)
    perror("landlock_create_ruleset");

/*
 * supervisor_fd can then be passed to landlock_add_rule, but it does not
 * work with landlock_restrict_self.  Not working for restrict_self means
 * that if a sandboxer accidentally passes the supervisor fd to the child,
 * it would not work in the same way as the supervisee fd, and therefore
 * the error is more discoverable.
 */
 if (landlock_add_rule(supervisor_fd, ...) < 0)
    perror("landlock_add_rule");

 /*
  * Any changes to the supervisor ruleset must be committed, even before
  * any child calls landlock_restrict_self().  Without committing, the
  * supervisor ruleset still behaves as if it is empty.
  */
 if (landlock_add_rule(supervisor_fd, ..., ...,
        LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR) < 0)
    perror("landlock_add_rule(COMMIT)");

/* Creates the supervisee ruleset */
int supervisee_fd = ioctl(supervisor_fd,
        LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET, /* flags= */ 0);
if (supervisee_fd < 0)
    perror("ioctl(LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET)");

pid_t child = fork();
if (child == 0) {
    /* The supervisor should not leak supervisor_fd to any untrusted code. */
    close(supervisor_fd);
    if (landlock_restrict_self(supervisee_fd, 0) < 0)
        perror("landlock_restrict_self");
    execve(...);
    perror("execve");
} else {
    close(supervisee_fd);
    /*
     * Here, the supervisor can add rules via landlock_add_rule(), Or
     * remove rules via landlock_add_rule() with
     * LANDLOCK_ADD_RULE_INTERSECT.
     *
     * Added rules doesn't come into effect until a final
     * landlock_add_rule() with commit flag (which may also just add a
     * dummy rule with access=0):
     */
    if (landlock_add_rule(supervisor_fd, ..., ..., LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR) < 0)
        perror("landlock_add_rule(COMMIT)");
}
```


Discussion on LANDLOCK_ADD_RULE_INTERSECT
-----------------------------------------

This was initially proposed by Mickaël, although now after writing some
example code against it [8], I'm not 100% sure that it is the most useful
uAPI.  For a supervisor based on some sort of config file, it already has
to track which rules are added to know what to remove, and thus I feel
that it would be easier (both to use and to implement) to have an API that
simply "replaces" a rule, rather than do a bitwise AND on the access.

Another alternative is to have neither intersect nor replace on individual
rules, but simply have a "clear all rules in this ruleset" flag.  This
allows the supervisor to not have to track what is already allowed - if it
reloads the config file, it can simply clear the ruleset, re-add all rules
based on the config, then commit it.  Although I fear that this might make
implementing some other use cases more difficult.

(We can of course implement both)


[8]: https://github.com/micromaomao/linux-dev/blob/94477974c616126762f24cc268967d7f989cc96d/samples/landlock/supervisor_sandboxer.c#L437-L481


Why require a commit operation?
-------------------------------

This is not a strictly necessary requirement with an rbtree based
implementation - it can be made thread-safe with RCU while still allowing
lockless access checks without too much overhead (although the code is
indeed a lot more tricky to write).  However, there is a possibility that
the domain lookup might become a hashtable with some future enhancement [9],
at which point it would be better to have an explicit commit operation to
avoid rebuilding the hashtable for every landlock_add_rule().  Having a
commit operation will likely also make some atomicity properties easier to
achieve, depending on the supervisor's needs.

I've actually previously implemented [10] a hashtable based ruleset, but
after benchmarking it I did not find a very significant performance
improvement (2.2% with 10 dir depth and 10 rules, 8.6% with 29 depth and
1000 rules) [11] compared with the complexity of the changes required.
After discussion with Mickaël I've decided to not pursue it for now, but
I'm open to suggestions.  If Mickaël and Günther are open to taking it, I
can revive the patch.


[9]:  https://github.com/landlock-lsm/linux/issues/1
[10]: https://lore.kernel.org/all/cover.1751814658.git.m@maowtm.org/
      Note that the benchmark posted here was inaccurate, due to the
      relatively high cost of kfunc probes compared to the work required
      to handle one openat().  For a more proper benchmark, refer to the
      comment below:
[11]: https://github.com/landlock-lsm/landlock-test-tools/pull/17#issuecomment-3594121269
      See specifically the collapsed section "parse-microbench.py
      base-vm.log arraydomain-vm.log"


Proposed implementation
-----------------------

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


## Future work

Implement hash table or not?

Supervisor notification: uAPI - new uAPI or fanotify?

Do mutable domains or supervisor notification first?
