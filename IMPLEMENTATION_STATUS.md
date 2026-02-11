# Supervisor Notification Implementation Status

## Overview

This document describes the implementation status of the Landlock supervisor notification mechanism as requested in the problem statement. The implementation enables supervisors to receive events when access is denied and respond dynamically.

## What Has Been Implemented

### 1. Core Data Structures (supervise.h)

- `struct landlock_supervisor_notif`: Manages notification state with event queues
- `struct landlock_supervise_event_kernel`: Kernel representation of notification events
- Event states: NEW, NOTIFIED, ALLOWED, DENIED
- Reference counting for proper lifecycle management

### 2. Supervisor Integration (supervisor.h/c)

- Extended `struct landlock_supervisor` with optional `notif` field
- Notification creation in `landlock_create_supervisor_notif()`
- Cleanup of notification state in supervisor teardown

### 3. uAPI Structures (include/uapi/linux/landlock.h)

- `LANDLOCK_CREATE_SUPERVISOR_NOTIFICATION` flag (bit 3)
- `struct landlock_supervise_event_hdr`: Event header with type, length, cookie
- `struct landlock_supervise_event`: Full event with FS/network details
- `struct landlock_supervise_response`: Response structure with allow/deny decision
- Event types: `LANDLOCK_SUPERVISE_EVENT_TYPE_FS_ACCESS` and `_NET_ACCESS`

### 4. Syscall Integration (syscalls.c)

- Flag validation for `LANDLOCK_CREATE_SUPERVISOR_NOTIFICATION`
- Notification state creation when flag is set
- `fop_supervisor_notif_read()`: Read events from supervisor fd
- `fop_supervisor_notif_write()`: Write responses to supervisor fd
- File operations wired to `supervisor_ruleset_fops`

### 5. Event Management (supervise.c)

- `landlock_queue_supervisor_event()`: Creates and queues events
- Event reference counting with `landlock_get/put_supervise_event()`
- Automatic denial of pending events on supervisor termination
- Wait queue for blocking reads

### 6. Documentation (design.md)

Comprehensive documentation covering:
- API usage and examples
- Event flow diagram
- Task work mechanism rationale
- Security considerations
- Integration with mutable domains

## What Still Needs Implementation

### 1. Task Work Mechanism

**File**: `security/landlock/task.c` (new) or `supervise.c`

Need to implement:
```c
void landlock_supervise_wait_work(struct callback_head *work)
{
    // Extract event from current->creds
    // Wait for supervisor response
    // If denied, force syscall to return -EPERM
    // If allowed, let syscall restart normally
}
```

### 2. FS Hook Integration

**File**: `security/landlock/fs.c`

Need to modify denial paths to:
1. Check if quiet flag is set → deny immediately if yes
2. Check if layer has supervisor with notifications → queue event and return -ERESTARTSYS
3. Set up task_work callback
4. Store event reference in task credentials

Example integration point (in `is_access_to_paths_allowed()`):
```c
// After determining access is denied by layer X
if (layer_masks[layer] & denied_mask) {
    if (layer_has_quiet_flag(layer)) {
        return false;  // Deny immediately
    }
    
    if (layer_has_supervisor_notifications(layer)) {
        struct landlock_supervise_event_kernel *event;
        
        event = landlock_queue_supervisor_event(
            domain->layer_stack[layer],
            LANDLOCK_SUPERVISE_EVENT_TYPE_FS_ACCESS,
            denied_mask, path, NULL, false, false, 0);
        
        if (!IS_ERR(event)) {
            // Store event in task credentials
            // Add task_work
            // Return special value to trigger -ERESTARTSYS
        }
    }
}
```

### 3. Credential Extension

**File**: `security/landlock/cred.h`

Add to `struct landlock_cred_security`:
```c
struct landlock_supervise_event_kernel *waiting_event;
```

This stores the event we're waiting for while task_work executes.

### 4. Sample Program Updates

**File**: `samples/landlock/supervisor_sandboxer.c`

Add:
- Event reading loop using `read()` on supervisor fd
- Event handling that prints denial information
- Response writing using `write()` on supervisor fd  
- "quiet" access type that sets `LANDLOCK_ADD_RULE_QUIET`
- Removal of quiet flag when rule is removed

Example skeleton:
```c
void handle_notifications(int supervisor_fd) {
    while (1) {
        struct landlock_supervise_event event;
        ssize_t ret = read(supervisor_fd, &event, sizeof(event));
        
        if (ret < 0) break;
        
        // Print denial
        fprintf(stderr, "Supervisor: %s access to [path] denied\n",
                access_to_string(event.access_request));
        
        // Deny it (don't update rules for now)
        struct landlock_supervise_response resp = {
            .length = sizeof(resp),
            .decision = 0,  // deny
            .cookie = event.hdr.cookie,
        };
        write(supervisor_fd, &resp, sizeof(resp));
    }
}
```

### 5. File Descriptor Handling

**File**: `syscalls.c` (`fop_supervisor_notif_read()`)

Currently marked TODO: Need to open O_PATH file descriptors for paths in events:
```c
// In fop_supervisor_notif_read(), when filling event:
if (event->type == LANDLOCK_SUPERVISE_EVENT_TYPE_FS_ACCESS) {
    if (event->target_1.dentry) {
        fd1 = get_unused_fd_flags(O_PATH | O_CLOEXEC);
        if (fd1 >= 0) {
            struct file *file = dentry_open(&event->target_1, O_PATH, current_cred());
            if (!IS_ERR(file))
                fd_install(fd1, file);
        }
    }
    // Similar for fd2
}
```

### 6. Network Hook Integration

**File**: `security/landlock/net.c`

Similar to FS hooks, need to check for supervisor notifications on denial and queue events with port information.

### 7. Syscall Restart Logic

**File**: `security/landlock/fs.c` and `net.c`

Need mechanism to return `-ERESTARTSYS` from hooks and have syscall restart. This may require:
- Returning a special error code
- Setting up signal handling
- Ensuring task_work executes before syscall restarts

## Testing Requirements

### Unit Tests
1. Create supervisor with notification flag
2. Read/write operations on supervisor fd
3. Event queueing and retrieval
4. Supervisor termination cleans up events

### Integration Tests
1. Supervisee triggers denial → event is queued
2. Supervisor reads event → gets correct information
3. Supervisor updates rules and allows → access succeeds on restart
4. Supervisor denies → access returns -EPERM
5. Quiet flag prevents notifications
6. Multiple layers with different supervisors

### Sample Program Test
1. Run supervisor_sandboxer with notification support
2. Trigger access denial in sandboxed process
3. Verify supervisor prints denial message
4. Verify access is actually denied

## Architecture Diagram

```
User Space                  Kernel Space
===========                 ============

Supervisor Process          Supervisee Process
     |                            |
     | landlock_create_ruleset    | landlock_restrict_self
     | (with NOTIF flag)           | (supervisee fd)
     |                            |
     v                            v
[supervisor_fd]              [domain with
     |                        supervisor layer]
     |                            |
     | read()                     | syscall (e.g., open)
     |                            |
     |                            v
     |                       [FS LSM hook]
     |                            |
     |                            | access denied?
     |                            | quiet? -> no
     |                            | has supervisor notif? -> yes
     |                            |
     |                            v
     |                     [landlock_queue_supervisor_event]
     |                            |
     |<------ event queued -------|
     |                            |
     |                            v
     |                     [return -ERESTARTSYS]
     |                            |
     |                            v
     |                     [task_work added]
     |                            |
     v                            v
[supervisor reads]          [task_work executes,
     |                       waits for response]
     |                            ^
     | write() response           |
     |--------------------------->|
                                  |
                                  v
                           [syscall restarts]
```

## Integration Approach

Recommended order of implementation:

1. **Add credential field** for storing waiting event
2. **Implement task_work callback** that waits for response
3. **Update one FS hook** (e.g., `hook_file_open`) as proof of concept
4. **Test with sample program** to verify end-to-end flow
5. **Add file descriptor handling** for path events
6. **Extend to all FS hooks** following the pattern
7. **Add network hook support**
8. **Handle edge cases** (supervisor death, multiple supervisors, etc.)

## Known Limitations

1. **File descriptor passing**: Current implementation doesn't open O_PATH fds for paths
2. **Destname support**: Variable-length filename handling not implemented
3. **Single supervisor**: Only youngest denying supervisor is notified
4. **No allow override**: Supervisor must update rules, can't directly allow one request
5. **Build testing**: No full kernel build performed to verify compilation

## Security Audit Checklist

- [ ] Notification state properly reference counted
- [ ] No memory leaks on supervisor termination
- [ ] No use-after-free of events
- [ ] Proper locking around notification queues
- [ ] Task work executes in correct context
- [ ] Can't DoS kernel by blocking in hooks
- [ ] Supervisor can't escape its own restrictions
- [ ] Race conditions between rule updates and notifications handled
- [ ] Quiet flag properly prevents notifications
- [ ] PID namespace handling for accessor PIDs

## Performance Considerations

1. **Event allocation**: Currently uses GFP_KERNEL_ACCOUNT for proper accounting
2. **Lock contention**: Notification queue uses spinlock, should be fine for low frequency
3. **Task work overhead**: One task_work per denial, acceptable for security mechanism
4. **FD allocation**: Opening O_PATH fds has some overhead, but unavoidable
5. **RCU synchronization**: No additional RCU overhead beyond existing supervisor commits

## Conclusion

The core infrastructure is in place and well-documented. The main remaining work is:
1. Connecting the notification system to the actual denial paths (FS/net hooks)
2. Implementing the task_work mechanism for async waiting
3. Adding file descriptor handling for path events
4. Updating the sample program to demonstrate usage

The design is sound and follows the requirements in the problem statement, particularly:
- No blocking in LSM hooks (task_work mechanism)
- Reading/writing supervisor ruleset fd directly (no separate supervisor fd)
- Quiet flag prevents notifications
- Two-phase approach (update rules, then respond)
