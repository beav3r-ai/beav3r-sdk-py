from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path


def load_demo_module():
    module_path = Path(__file__).resolve().parents[1] / "examples" / "agent_demo.py"
    src_path = str(Path(__file__).resolve().parents[1] / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
    spec = importlib.util.spec_from_file_location("agent_demo", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load agent_demo module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AgentDemoTests(unittest.TestCase):
    def test_load_bridge_env_uses_override_file(self) -> None:
        demo = load_demo_module()
        with tempfile.TemporaryDirectory() as tmp_dir:
            env_path = Path(tmp_dir) / "custom.env"
            env_path.write_text("BEAV3R_API_KEY=override_key\nIGNORED_LINE\n")

            old_env = os.environ.get("BEAV3R_ENV_FILE")
            os.environ["BEAV3R_ENV_FILE"] = str(env_path)
            try:
                self.assertEqual(demo.load_bridge_env(), {"BEAV3R_API_KEY": "override_key"})
            finally:
                if old_env is None:
                    os.environ.pop("BEAV3R_ENV_FILE", None)
                else:
                    os.environ["BEAV3R_ENV_FILE"] = old_env

    def test_load_bridge_env_finds_parent_dotenv(self) -> None:
        demo = load_demo_module()
        with tempfile.TemporaryDirectory() as tmp_dir:
            temp_root = Path(tmp_dir)
            script_dir = temp_root / "examples"
            script_dir.mkdir()
            fake_script = script_dir / "agent_demo.py"
            fake_script.write_text("# stub\n")
            (temp_root / ".env").write_text("BEAV3R_API_KEY=parent_key\n")

            original_file = demo.__file__
            demo.__file__ = str(fake_script)
            try:
                self.assertEqual(demo.load_bridge_env(), {"BEAV3R_API_KEY": "parent_key"})
            finally:
                demo.__file__ = original_file

    def test_main_help_exits_cleanly(self) -> None:
        demo = load_demo_module()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                demo.main(["--help"])

        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("Run a standalone Beav3r demo request", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
