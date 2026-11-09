"""``haltsql`` console script: runs the CLI bundled in a platform wheel.

Installed only by platform wheels (which ship ``haltsql/_native/haltsql``), so a
pure-Python install never puts a non-working ``haltsql`` on ``PATH`` in front of
a CLI installed some other way.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import List, Optional

from .local import bundled_binary


def main(argv: Optional[List[str]] = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    exe = bundled_binary()
    if exe is None:
        sys.stderr.write(
            "haltsql: this installation of the haltsql Python package has no bundled CLI "
            "(pure-Python wheel). Install a platform wheel (manylinux_2_28 x86_64/aarch64, "
            "macOS arm64) or the haltsql release binary.\n"
        )
        sys.exit(2)
    if os.name == "nt":  # no exec() that keeps the console semantics on Windows
        sys.exit(subprocess.call([exe, *args]))
    os.execv(exe, [exe, *args])


if __name__ == "__main__":  # pragma: no cover
    main()
