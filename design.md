Hi,

Recently I have been continuing work on the previously proposed Landlock
supervise feature (context below).  While I do have some rough PoCs, and
I'm aware that sometimes code is better than talk, because of the amount
of work involved, I would like to get some early feedback on the design
before continuing.

Scrappy demo (just screencasts):

- user-space implemented "permissive mode":
    https://fileshare.maowtm.org/landlock-20260214/demo.mp4
- mutable domains based on a reloadable config file:
    https://fileshare.maowtm.org/landlock-20260213/demo.mp4

While I would be glad to receive reviews from anyone, Günther, when you
are not too busy, can you kindly give this a review?  A lot of this has
already been discussed with Mickaël, in fact a large part of this design
was from his suggestions.  I apologize in advance for the length of this
email - please feel free to respond whenever you have time to.

PoC code used in the above videos are largely generated, somewhat buggy,
and unreviewed, but they are available:

- mutable domains:
    https://github.com/micromaomao/linux-dev/pull/26/changes
- supervisor notification:
    https://github.com/micromaomao/linux-dev/pull/27/changes

The motivations listed in [1] are still relevant, and to add to that, here
are some additional examples of things we can do with the supervisor
feature (all from unprivileged applications):

- Implmenting a version of StemJail [2] which does not rely on bind mounts
  and LD_PRELOAD (for the notification part, not for access control).  Or
  in fact, any other uses of LD_PRELOAD for the purpose of finding out
  what files are accessed.

- For island [3], some sort of denial logging tied to the context,
  integrated in the tool itself (rather than through kernel audit) and
  live config reload.

- Use in a non-security related context, such as automated build
  dependency tracking.

[1]: https://lore.kernel.org/all/cover.1741047969.git.m@maowtm.org/
[2]: https://github.com/stemjail/stemjail
[3]: https://github.com/landlock-lsm/island


Background
----------

A while ago I sent a "Landlock supervise" RFC patch series [1], in which I
proposed to extend Landlock with additional functionality to support
"interactive" rule enforcement.  In discussion with Mickaël, we decided to
split this work into 3 stages:  quiet flag, mutable domains, and finally
supervisor notification.  Relevant discussions are at [4] and in replies
to [1].

The patch for quiet flag [5] has gone through multiple review iterations
already.  It is useful on its own, but it was also motivated by the
eventual use in controlling supervisor notification.

The next stage is to introduce "mutable domains".  The motivation for this
is two fold:

1. This allows the supervisor to allow access to (large) file hierarchies
   without needing to be woken up again for each access.
2. Because we cannot block within security_path_mknod and other
   directory-modification related hooks [6], the proposal was to return
   immediately from those hooks after queuing the supervisor notification,
   then wait in a separate task_work.  This however means that we cannot
   directly "allow" access (and even if we can, it may introduce TOCTOU
   problems).  In order to allow access to requested files, the supervisor
   has to add additional rules to the (now mutable) domain which will
   allow the required access.

[1]: https://lore.kernel.org/all/cover.1741047969.git.m@maowtm.org/
[4]: https://github.com/landlock-lsm/linux/issues/44
[5]: https://lore.kernel.org/all/cover.1766330134.git.m@maowtm.org/
[6]: https://lore.kernel.org/all/20250311.Ti7bi9ahshuu@digikod.net/


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
own (although it does make it significantly more useful).  This will be
the step after mutable domains, if we keep with the plan previously
discussed with Mickaël.


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
example code against it [7], I'm not 100% sure that it is the most useful
uAPI.  For a supervisor based on some sort of config file, it already has
to track which rules are added to know what to remove, and thus I feel
that it would be easier (both to use and to implement) to have an API that
simply "replaces" a rule, rather than do a bitwise AND on the access.

Another alternative is to simply have a "clear all rules in this ruleset"
flag.  This allows the supervisor to not have to track what is already
allowed - if it reloads the config file, it can simply clear the ruleset,
re-add all rules based on the config, then commit it.  Although I worry
that this might make implementing some other use cases more difficult.

(We can of course implement both)

[7]: https://github.com/micromaomao/linux-dev/blob/94477974c616126762f24cc268967d7f989cc96d/samples/landlock/supervisor_sandboxer.c#L437-L481


Why require a commit operation?
-------------------------------

This is not a strictly necessary requirement with an rbtree based
implementation - it can be made thread-safe with RCU while still allowing
lockless access checks without too much overhead (although the code is
indeed more tricky to write).  However, there is a possibility that the
domain lookup might become a hashtable with some future enhancement [8],
at which point it would be better to have an explicit commit operation to
avoid rebuilding the hashtable for every landlock_add_rule().  Having a
commit operation will likely also make some atomicity properties easier to
achieve, depending on the supervisor's needs.

I've actually previously implemented hashtable domains [9], but after
benchmarking it I did not find a very significant performance improvement
(2.2% with 10 dir depth and 10 rules, 8.6% with 29 depth and 1000 rules) [10]
especially considering the complexity of the changes required.  After
discussion with Mickaël I've decided to not pursue it for now, but I'm
open to suggestions.  If Mickaël and Günther are open to taking it, I can
revive the patch.

[8]:  https://github.com/landlock-lsm/linux/issues/1
[9]:  https://lore.kernel.org/all/cover.1751814658.git.m@maowtm.org/
      Note that the benchmark posted here was inaccurate, due to the
      relatively high cost of kfunc probes compared to the work required
      to handle one openat().  For a more proper benchmark, refer to the
      comment below:
[10]: https://github.com/landlock-lsm/landlock-test-tools/pull/17#issuecomment-3594121269
      See specifically the collapsed section "parse-microbench.py
      base-vm.log arraydomain-vm.log"


Proposed implementation
-----------------------

In order to store additional data and locks for the supervisor, we create
a new `struct landlock_supervisor`.  Both the supervisor and supervisee
rulesets, and the landlock_hierarchy of each layer, will point to this
struct.  (A future revision may optimize on this to reduce pointer chasing
when needing to check supervisor rulesets of parent layers.)

One of the main tricky areas of this work is the implementation of
LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR and the access checks.  We want:

- atomic commit: the supervised program should not "experience" any rule
  changes until they are committed, and once it is committed it should see
  all the changes together

- lockless access checks (even when the supervisee ruleset does not allow
  the access, necessitating checking the supervisor rulesets, this should
  still not involve any locks)

- atomic access checks: an access check should either be completely based
  on the "old" rules or the "new" rules, even if a commit happens in the
  middle of a path walk.  This prevents incorrect denials when a commit
  moves a rule from /a to /a/b when we've just finished checking /a/b and
  about to check /a.

In order to achieve atomic commit, the supervisor fd cannot actually point
to (and thus allow editing) the "live" ruleset.  Instead, when a
`LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR` is requested, a new `struct
landlock_ruleset` is created, the rules are copied over from the existing
supervisor ruleset, and the pointer in the landlock_supervisor is swapped.

In order to keep access checks lockless (as it is currently), the live
ruleset pointer needs to be RCU-protected.  To reduce complexity, this
initial implementation uses synchronize_rcu() directly in the calling
thread of `LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR`, and frees the old
supervisor ruleset afterwards, but this can be rewritten to use call_rcu()
in a future iteration if necessary (which will allow quicker commits,
which can be quite impactful if we use this to auto-generate rulesets).

During access checks, for each step of the path walk, after
landlock_unmask_layers()-ing the supervisee rule, if the access is not
already allowed, we check for rules in the supervisor ruleset and
effectively does landlock_unmask_layers() on them too.

In order to have atomic access checks, we need to pre-capture the
supervisor committed ruleset pointers for all layers at the start of the
path walk (in `is_access_to_paths_allowed`).  Storing this on the stack,
this takes the space of 16 pointers, hence 128 bytes on 64-bit (I'm keen
to hear suggestions on how best to mitigate this).  Another effect of this
"caching" is that in order to be able to release rcu in the path walk
(which is required for the path_put()), we actually need to take refcount
on the committed ruleset (and free it at the end of
is_access_to_paths_allowed).

Optional access (truncate and ioctl) handling is also tricky.  There are
two possible alternatives:

- The allowed optional actions are still entirely determined at file open
  time.  This likely works in the majority of cases, where truncate (and
  maybe also ioctl) are given or taken away together with write access.
  However, this may mean that we need to send an access request
  notification immediately at open() time if e.g. write access is given
  but truncate (or ioctl) is not, even if truncate (or ioctl) is not
  attempted yet, since the supervisor would not be able to allow it later.
  (or alternatively we can choose to not send this notification, and the
  supervisor will just have to "know" to add truncate/ioctl rights if
  required, in advance.)

- The allowed optional actions are considered to be determined at
  operation time (even though for a static ruleset it is cached).  This
  means that for supervised layers, we will always have to re-check their
  supervisor rulesets, whether or not the access was initially allowed,
  which will involve doing a path walk.  This does however means that the
  supervisor can be notified "in the moment" when a truncate (or more
  likely to be relevant - ioctl) is attempted.


Supervisor notification
-----------------------

The above RFC only covers mutable domains.  The natural next stage of this
work is to send notification to the supervisor on access denials, so that
it can decide whether to allow the access or not.  For that, there are
also lots of questions at this stage:


- Should we in fact implement that first, before mutable domains?  This
  means that the supervisor would only be able to find out about denials,
  but not allow them without a sandbox restart.  We still eventually want
  the mutable domains, since that makes this a lot more useful, but I can
  see some use cases for just the notification part (e.g. island denial
  log), and I can't see a likely use case for just mutable domains, aside
  from live reload of landlock-config (maybe that _is_ useful on its own,
  considering that you can also find out about denials from the kernel
  audit log, and add missing rules based on that).


- Earlier when implementing the Landlock supervise v1 RFC, I basically
  came up with an ad-hoc uAPI for the notification [11], and the PoC code
  linked to above also uses this uAPI.  There are of course many problems
  with this as it stands, e.g. it only having one destname, which means
  that for rename, the fd1 needs to be the child being moved, which does
  not align with the vfs semantic and how Landlock treat it (i.e. the
  thing being updated here is the parent directory, not the child itself).

  But also, in discussion with Mickaël last year, he mentioned that we
  could reuse the fsnotify infrastructure, and perhaps additionally, use
  fanotify to deliver these notifications.  I do think there is some
  potential here, as fanotify already implements an event header, a
  mechanism for receiving and replying to events, etc.  We could possibly
  extend it to send Landlock specific notifications via a new kind of mark
  (FAN_MARK_LANDLOCK_DOMAIN ??) and add one or more new corresponding
  event types.  Mickaël mentioned mount notifications [12] as an example
  of using fanotify to send notifications other than file/dir
  modifications.

  I'm not sure if directly extending the fanotify uAPI is a good idea tho,
  considering that Landlock is not a feature specific to the filesystem -
  we will also have denial events for net_port rules, and perhaps more in
  the future.  However, Mickaël mentioned that there might be some
  internal infrastructure which we can re-use (even if we have our own
  notification uAPI).


- The other uAPI alternative which I have been thinking of is to extend
  seccomp-unotify.  For example, a Landlock denial could result in the
  syscall being trapped and a `struct seccomp_notif` being sent to the
  seccomp supervisor (via the existing mechanism), with additional
  information (mostly, the file(s) / net ports being accessed and access
  rights requested) attached to the notification _somehow_.  Then the
  supervisor can use the same kind of responses one would use for
  seccomp-unotify to cause the syscall to either be retried (possibly via
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE`) or return with an error code of its
  choice (or alternatively, carry out the operation on behalf of the
  child, and pretend that the syscall succeed, which might be useful to
  implement an "allow file creation but only this file" / "allow `mktemp
  -d` but not arbitrary create on anything under /tmp").

  Looking at `struct seccomp_notif` and `struct seccomp_data` however, I'm
  not sure how feasible / doable this extension would be.  Also,
  seccomp-unotify is supposed to trigger before a syscall is actually
  executed, whereas if we use it this way, we will want it to trigger
  after we're already midway through the syscall (in the LSM hook).  This
  might make it hard to implement (and also twists a bit the uAPI
  semantics of seccomp-unotify).


I'm not sure how sensible the above uAPI suggestions are.  Are there any
immediate reasons, from Landlock's perspective, to rule out either of
them?  (I will probably wait for at least a first review from the Landlock
side before directing this explicitly to the fanotify and/or
seccomp-unotify maintainers, but if somehow a maintainer/reviewer from
either of those areas are already reading this, feedback would be very
valuable :D )

[11]: https://lore.kernel.org/all/cde6bbf0b52710b33170f2787fdcb11538e40813.1741047969.git.m@maowtm.org/#iZ31include:uapi:linux:landlock.h
[12]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?h=v6.15-rc1&id=fd101da676362aaa051b4f5d8a941bd308603041
