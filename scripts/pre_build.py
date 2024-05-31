# ruff: noqa: INP001 # there is no need to import anything scripts/
import subprocess  # noqa: S404
import sys
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class SpecialBuildHook(BuildHookInterface):
    PLUGIN_NAME = "pre_build"

    @staticmethod
    def initialize(version, build_data):  # noqa: ARG004 # overrides externally defined method
        try:
            command = [
                Path("~/.local/bin/configle").expanduser().resolve(),
                Path("~/.config/mypy/config/global.ini").expanduser().resolve(),
                Path("./mypy.local.ini").resolve(),
                "-o",
                "mypy.ini",
            ]
            print(f"build.py: {" ".join(f"{e:s}" for e in command)}")
            result = subprocess.run(command, check=True)  # noqa: S603
            if result.returncode != 0:
                print("build.py: script returned non-zero exit code.", file=sys.stderr)
                sys.exit(result.returncode)

            result = subprocess.run(["/usr/bin/git", "add", "mypy.ini"], check=True)  # noqa: S603

        except subprocess.CalledProcessError as e:
            print(f"build.py: subprocess exception: {e}", file=sys.stderr)
            sys.exit(e.returncode)
