from hatchling.builders.hooks.plugin.interface import BuildHookInterface
import subprocess
import sys


class SpecialBuildHook(BuildHookInterface):
    PLUGIN_NAME = "pre_build"

    def initialize(self, version, build_data):
        try:
            command = ["configle", "~/.config/mypy/config/global.ini", "./mypy.local.ini", "-o", "mypy.ini"]
            print(f"build.py: {" ".join(command)}")
            result = subprocess.run(command, check=True)
            if result.returncode != 0:
                print("build.py: script returned non-zero exit code.", file=sys.stderr)
                sys.exit(result.returncode)

            result = subprocess.run(["git", "add", "mypy.ini"], check=True)

        except subprocess.CalledProcessError as e:
            print(f"build.py: subprocess exception: {e}", file=sys.stderr)
            sys.exit(e.returncode)
