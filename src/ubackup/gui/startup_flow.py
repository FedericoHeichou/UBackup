from __future__ import annotations

"""Non-visual state decisions for the one-use GUI startup stream."""


class StartupFlow:
    def __init__(self, active: bool) -> None:
        self.state = "pending" if active else "inactive"
        self.root_complete = False

    def accept_frame(self, frame: object) -> bool:
        return self.state == "pending" and isinstance(frame, dict) and frame.get("type") == "result"

    def mark_root_complete(self) -> None:
        if self.state == "pending":
            self.root_complete = True

    def succeed(self) -> bool:
        if self.state != "pending":
            return False
        self.state = "success"
        return True

    def fail(self) -> bool:
        if self.state != "pending":
            return False
        self.state = "failed"
        return True

    def cancel(self) -> bool:
        if self.state != "pending":
            return False
        self.state = "cancelled"
        return True

    @property
    def blocks_root_expansion(self) -> bool:
        return self.state == "pending"
