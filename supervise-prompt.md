Implement the supervisor notification mechanism as alluded to in design.md.  There is actually prior work, and the detail of this implementation should follow that when it makes sense to (and especially the uAPI).

## Previous implementation

Earlier, I implemented a supervisor mechanism without mutable domains support in the "landlock-supervise" branch which you can check via `git fetch --depth=11 origin landlock-supervise landlock-supervise-base` then `git log landlock-supervise-base..landlock-supervise` then `git show` individual commits, or you can use git show 9dc2b112c4be1aadff612b226c603db66ef79955:file to view individual changed files (9dc2b112c4be1aadff612b226c603db66ef79955 is the last commit in that PR. Of course you still need to fetch the branch with --depth=11 to read it).

## What I want

Please follow this previous implementation while rebasing the work on top of this new branch which contains mutable domain changes, and also changing it in the way I will describe below.  The end result should be that a Landlock supervisor can use the mutable domain feature to make dynamic policy changes, and it can also use the notification mechanism to receive events telling it that an app is trying to access something it is not allowed to. The event should be sent to all the denying layer's supervisor (if there is one) if the request is not allowed by either that layer's supervisee ruleset or that layer's supervisor ruleset. The interface should be the same as the one in the landlock-supervise branch, except that now we read from / write to the supervisor ruleset directly, instead of a supervisor file descriptor created in a new int value in the landlock_ruleset_attr. Also, we need a new LANDLOCK_CREATE_SUPERVISOR_NOTIFICATION flag to determine whether a supervised layer's supervisor actually wants to receive notifications (if not, outright denial).

The other change I want to make is how the waiting works. Previously, the thread blocks in the LSM hook until the supervisor responds, which can cause (unprivileged) DoS since hooks like mknod are called with the inode lock of the parent directory held. Here is a fix proposal:

An approach would be to add a task_work (executed before
returning to user space) that will wait for the supervisor to take a
decision, and in the meantime the LSM hook would return -ERESTARTNOINTR
for the syscall to start again after the wait.  However, because the
request to the supervisor would be called outside of the hook, it should
not be possible to directly allow the request (because of race
condition) but to update the domain accordingly (although the supervisor can also tell the kernel to reject the request and just return -EPERM)

Later on, we have this description of the new approach:

```
for_each_set_bit layer in denied_layers but in reverse order (youngest layer i.e. larger layer_level first) {
  if (collected_rule_flags->quiet_layers[layer]) {
    // The quiet flag would now also serve the purpose of preventing supervisor notifications (in addition to its original use case in audit log suppression)
    return deny;
  }
  if (layer supervisor does not have notification enabled) { // note that a layer can still have a supervisor that can cause mutable domain changes, without opting in to receiving denial notifications.
    audit_denial(layer, ...);
    return deny;
  }
}

// by this point all denied layers are supervised, so ask them
find last (youngest) layer that denied
queue supervisor event for supervisor of layer
wake up that supervisor
landlock_creds(current->creds)->landlock_waiting_on_supervisor_event = event
add task work landlock_supervise_wait_work;
return -ERESTARTSYSNOINTR;

void landlock_supervise_wait_work() {
    struct landlock_supervise_event_kernel evt = landlock_creds(current->creds)->...
    int answer = wait_for_supervisor();
    if (answer == deny) {
      audit_denial(layer, ...);
      // somehow sets return code of syscall to -EPERM
      return;
  }
```

To make this design easier, we only wait for one supervisor at a time. If, for example, layer 1 and 2 both deny the request and they are both supervised layers, send a notification to layer 2 first and return from the hook. If it allows access, the next restart of this syscall will end up calling layer 1's supervisor.

Since Landlock has many different hooks, we should create a function to do as much of the common supervisor related work as possible, and call it in e.g. is_access_to_paths_allowed() and other places (and net) if necessary. Remember to refer to the old landlock-supervise implementation. We don't have to notify scope related denials, or attempted mounts. Also don't worry about selftests for now.

## Additional changes

Please also add the detailed design for the supervisor notification feature (the one you implemented) to design.md.

Please also extend supervisor_sandboxer.c in this way:
- Set up supervisor notification
- When an event is received, print to stderr a message like "Supervisor: read (or 'read-write') access to /path denied"
- Deny it outright
- Accept a new "access" called "quiet" which doesn't grant any access, just sets the quiet flag on a file/dir. e.g. a line in the config can say `quiet /tmp`
- Remove the quiet flag if this line is later removed, like how we remove access.

Please also try to update documentations.
