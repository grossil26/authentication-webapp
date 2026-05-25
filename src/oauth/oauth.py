import subprocess
from pathlib import Path
import sys

class OAuthToolkit:
    """
    OAuth Module for interacting and replaying OAuth attacks

    Args:
        tool: Implicit / Redirect / State
        script_path: The Path to the script location
    """

    def __init__(self, tool):
        self.tool = tool

        scripts = {
            "implicit": "implicit_flow",
            "redirect": "redirect_uri",
            "state": "state_check",
        }

        if tool not in scripts:
            print("Invalid Tool")
            sys.exit(1)

        self.script_path = Path(__file__).parent / f"{scripts[tool]}.py"

    def __call__(self):
        try:
            result = subprocess.Popen(
                ["mitmdump", "-s", str(self.script_path)],
            )
        except FileNotFoundError:
            print("Error: mitmdump not found. Is mitmproxy installed?")
            sys.exit(1)
        except OSError as e:
            print(f"Error: Failed to start process: {e}")
            sys.exit(1)

        try:
            result.wait(timeout=0.5)
            print(f"Script failed with code {result.returncode}")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            print(f"Script started successfully (PID: {result.pid})")

        try:
            result.wait()
        except KeyboardInterrupt:
            print("\nInterrupt received, shutting down...")
            result.terminate()
            try:
                result.wait(timeout=5)
                print("Process terminated cleanly.")
            except subprocess.TimeoutExpired:
                print("Process did not terminate in time, killing it.")
                result.kill()
                result.wait()
            sys.exit(0)