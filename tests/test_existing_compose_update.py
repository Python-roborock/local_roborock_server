"""Exercise the updater without Docker, a real checkout, or robot credentials."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


FAKE_COMMAND = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['MOCK_TRACE'], 'a') as f:
    f.write(json.dumps([name, *args]) + '\n')
if name == 'git':
    if 'archive' in args: sys.stdout.buffer.write(b'committed source')
    if 'rev-parse' in args: print('a' * 40)
    if 'diff' in args and os.environ['MOCK_MODE'] == 'dirty': sys.exit(1)
    sys.exit(0)
if 'inspect' in args and '--format' in args:
    fmt = args[args.index('--format') + 1]
    if 'Labels' in fmt: print(json.loads(os.environ['MOCK_LABELS']).get(fmt.split('"')[1], ''))
    elif '.Config.Image' in fmt: print('local/test:schedule-ui')
    elif '.State.Health' in fmt: print('healthy')
elif args and args[0] == 'build':
    sys.stdin.buffer.read()
    if os.environ['MOCK_MODE'] == 'build_failure': sys.exit(4)
elif args and args[0] == 'compose' and 'config' in args:
    image = 'other:image' if os.environ['MOCK_MODE'] == 'image_mismatch' else 'local/test:schedule-ui'
    print(json.dumps({'services': {'roborock-local-server': {'image': image}}}))
'''


class ExistingComposeUpdateTests(unittest.TestCase):
    def test_existing_config_is_reused_and_failures_do_not_restart(self):
        source = Path(__file__).resolve().parents[1] / "scripts/update-existing-compose.sh"
        for mode in ("success", "build_failure", "image_mismatch", "dirty"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                repo = base / "repo"
                repo.mkdir()
                runtime = base / "runtime"
                runtime.mkdir()
                (runtime / ".env").write_text("kept settings")
                (runtime / "SOURCE_COMMIT").write_text("previous-revision\n")
                (runtime / "credentials.json").write_text("keep working credentials")
                project = base / "project with spaces"
                project.mkdir()
                files = [project / "compose.yaml", project / "override.yaml"]
                for path in files:
                    path.write_text("kept configuration")
                bindir = base / "bin"
                bindir.mkdir()
                for command in ("git", "docker"):
                    path = bindir / command
                    path.write_text(FAKE_COMMAND)
                    path.chmod(0o755)
                path = bindir / "sudo"
                path.write_text('#!/bin/bash\nif [[ "$1" == -v ]]; then exit 0; fi\nexec "$@"\n')
                path.chmod(0o755)
                trace = base / "trace.jsonl"
                env = {**os.environ, "PATH": str(bindir) + ":" + os.environ["PATH"], "MOCK_TRACE": str(trace),
                       "MOCK_MODE": mode, "ROBOROCK_RUNTIME_DIR": str(runtime),
                       "MOCK_LABELS": json.dumps({"com.docker.compose.project": "existing-project",
                           "com.docker.compose.service": "roborock-local-server",
                           "com.docker.compose.project.working_dir": str(project),
                           "com.docker.compose.project.config_files": ",".join(map(str, files))})}
                result = subprocess.run(["bash", str(source), str(repo)], env=env, text=True, capture_output=True, timeout=15)
                commands = [json.loads(line) for line in trace.read_text().splitlines()]
                restarts = [item for item in commands if item[:2] == ["docker", "compose"] and "up" in item]
                if mode == "success":
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(len(restarts), 1)
                    for argument in ("--no-deps", "--no-build", "--force-recreate", "never", str(runtime / ".env"), *map(str, files)):
                        self.assertIn(argument, restarts[0])
                    self.assertEqual((runtime / "SOURCE_COMMIT").read_text().strip(), "a" * 40)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(restarts)
                    self.assertEqual((runtime / "SOURCE_COMMIT").read_text(), "previous-revision\n")
                self.assertEqual((runtime / "credentials.json").read_text(), "keep working credentials")
                self.assertTrue(all(path.read_text() == "kept configuration" for path in files))


if __name__ == "__main__":
    unittest.main()
