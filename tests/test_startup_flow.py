from ubackup.gui.startup_flow import StartupFlow


def test_startup_flow_blocks_root_until_terminal_and_suppresses_late_frames():
    flow = StartupFlow(True)
    assert flow.blocks_root_expansion
    assert flow.accept_frame({"type": "result"})
    flow.mark_root_complete()
    assert flow.succeed()
    assert not flow.blocks_root_expansion
    assert not flow.accept_frame({"type": "result"})
    assert not flow.fail()


def test_startup_flow_failure_and_cancel_are_exclusive():
    failed = StartupFlow(True)
    assert failed.fail()
    assert not failed.succeed()
    cancelled = StartupFlow(True)
    assert cancelled.cancel()
    assert not cancelled.succeed()


def test_inactive_flow_allows_later_root_expansion():
    flow = StartupFlow(False)
    assert not flow.blocks_root_expansion
    assert not flow.accept_frame({"type": "result"})
