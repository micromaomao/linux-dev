import gdb
from linux import utils, cpus

def on_stop_update_thread_names(event: gdb.StopEvent):
    # we only do this for qemu gdb, since kgdb has individual threads for each task anyway (they're just named badly)
    if utils.get_gdbserver_type() == utils.GDBSERVER_QEMU:
        if utils.is_target_arch("x86"):
            threads = gdb.selected_inferior().threads()
            for t in threads:
                cpu = t.num - 1
                task = cpus.get_current_task(cpu)
                if task:
                    t.name = f"{task['comm'].string()}[{int(task['pid'])}]"
        return

def on_cont_clear_thread_names(event: gdb.ContinueEvent):
    if utils.get_gdbserver_type() == utils.GDBSERVER_QEMU:
        threads = gdb.selected_inferior().threads()
        for t in threads:
            t.name = None

gdb.events.stop.connect(on_stop_update_thread_names)
gdb.events.cont.connect(on_cont_clear_thread_names)
