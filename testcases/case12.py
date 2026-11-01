import subprocess


def list_directory(path):
    result = subprocess.run(["ls", "-l", "--", path], capture_output=True, text=True, check=False)
    return result.stdout
