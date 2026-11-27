"""Run the HENIX browser regressions against an isolated local workspace."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import Handler, Workspace, WorkspaceServer
from tests.fixtures import training_capture


def main():
    node = shutil.which("node")
    if not node:
        sys.exit("Install Node.js for the browser checks.")
    with tempfile.TemporaryDirectory(prefix="henix-browser-") as folder:
        directory = Path(folder)
        fixture = directory / "browser.cap"
        fixture.write_bytes(training_capture())
        workspace = directory / "workspace"
        workspace.mkdir()
        with WorkspaceServer(("127.0.0.1", 0), Handler) as server:
            server.workspace = Workspace(workspace)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            env = dict(os.environ, PYTHON=sys.executable, HENIX_FIXTURE=str(fixture),
                       HENIX_URL=f"http://127.0.0.1:{server.server_port}")
            try:
                for suite in ("workspace.cjs", "large-ui.cjs"):
                    subprocess.run([node, str(ROOT / "tests" / "browser" / suite)],
                                   check=True, cwd=ROOT, env=env, timeout=240)
            finally:
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    main()
