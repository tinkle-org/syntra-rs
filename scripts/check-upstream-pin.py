"""Read-only scoped SDD provenance and implementation-owned input check.

Uses SYNTRA_SDD_ROOT or ../syntra, reading exact pinned Git blobs even if HEAD
has advanced. --offline checks only local proto/test-asset digests.
"""

import subprocess
import sys

# A read-only check must not create a local bytecode cache on first import.
sys.dont_write_bytecode = True

from upstream_snapshot import main


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"Upstream pin check failed: {error}")
