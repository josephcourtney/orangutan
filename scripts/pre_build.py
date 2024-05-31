import subprocess
import sys


def pre_build():
    try:
        command = ["configle", "~/.config/mypy/config/global.ini", "./mypy.local.ini", "-o", "mypy.ini"]
        print(f"build.py: {" ".join(command)}")
        result = subprocess.run(command, check=True)
        if result.returncode != 0:
            print("build.py: script returned non-zero exit code.", file=sys.stderr)
            sys.exit(result.returncode)
    except subprocess.CalledProcessError as e:
        print(f"build.py: subprocess exception: {e}", file=sys.stderr)
        sys.exit(e.returncode)


if __name__ == "__main__":
    pre_build()
