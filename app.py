
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.get("/diagnostics")
def diagnostics():
    # Intentionally vulnerable: user input reaches a shell command.
    target = request.args.get("target", "localhost")
    result = subprocess.run(
        "ping -c 1 " + target,
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
