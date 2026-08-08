from __future__ import annotations

import sys

if __name__ == "__main__" and __package__ in {None, ""}:
    sys.path.insert(0, "/usr/lib/ubackup")

from ubackup.privileged.restore import handle_restore_inplace, validate_inplace_payload
from ubackup.privileged.runtime import run_fixed_helper


def main(argv: list[str] | None = None) -> int:
    return run_fixed_helper(
        sys.argv[1:] if argv is None else argv,
        operation="restore-inplace",
        payload_validator=validate_inplace_payload,
        handler=handle_restore_inplace,
    )


if __name__ == "__main__":
    raise SystemExit(main())
