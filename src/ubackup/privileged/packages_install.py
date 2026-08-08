from __future__ import annotations

import sys

if __name__ == "__main__" and __package__ in {None, ""}:
    sys.path.insert(0, "/usr/lib/ubackup")

from ubackup.privileged.restore import handle_packages_install, validate_packages_payload
from ubackup.privileged.runtime import run_fixed_helper


def main(argv: list[str] | None = None) -> int:
    return run_fixed_helper(
        sys.argv[1:] if argv is None else argv,
        operation="packages-install",
        payload_validator=validate_packages_payload,
        handler=handle_packages_install,
    )


if __name__ == "__main__":
    raise SystemExit(main())
