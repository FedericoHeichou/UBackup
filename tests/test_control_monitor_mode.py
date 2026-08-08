import os
import time

from ubackup.privileged.runtime import _ControlMonitor


def test_control_monitor_restores_descriptor_blocking_mode():
    read_fd, write_fd = os.pipe()
    try:
        assert os.get_blocking(read_fd) is True
        monitor = _ControlMonitor(read_fd, deadline=time.monotonic() + 1)
        monitor.start()
        assert os.get_blocking(read_fd) is False
        monitor.close()
        assert os.get_blocking(read_fd) is True
    finally:
        os.close(read_fd); os.close(write_fd)
