"""Read-only content check for the accepted Syntra schema and suite snapshot.

The historical extraction/review pins belong in MIGRATION.md. The active
contract pin and every snapshot digest live in upstream.lock.json; the reviewed
identity is also checked by upstream_snapshot.py. Use --upstream ../syntra to
add comparison with the committed upstream Git blobs, independent of worktrees.
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
