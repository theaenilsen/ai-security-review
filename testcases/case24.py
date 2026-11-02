import shlex
import subprocess


def search_log(pattern):
    command = "grep -- " + shlex.quote(pattern) + " /var/log/app.log"
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
