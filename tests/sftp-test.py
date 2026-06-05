#!/usr/bin/env python3
"""SFTP/SSH protocol end-to-end test using subprocess."""
import os
import subprocess
import sys
import time

HOST = "127.0.0.1"
SFTP_PORT = 30082
USER = "testuser"
PASSWORD = "testuser-pass"

SFTP_TEST_DIR = "/tmp/sftp_test_xxx"
os.makedirs(SFTP_TEST_DIR, exist_ok=True)

# Create test file
test_file = os.path.join(SFTP_TEST_DIR, "test_upload.txt")
with open(test_file, "w") as f:
    f.write(f"hello sftp test {time.time()}\n")

# Use sftp batch mode with password via SSH_ASKPASS
# First create askpass script
askpass_script = os.path.join(SFTP_TEST_DIR, "askpass.sh")
with open(askpass_script, "w") as f:
    f.write(f"#!/bin/sh\necho '{PASSWORD}'\n")
os.chmod(askpass_script, 0o755)

# Use sftp -b for batch mode
batch_file = os.path.join(SFTP_TEST_DIR, "batch.txt")
remote_file = "test_sftp_upload.txt"
with open(batch_file, "w") as f:
    f.write(f"ls -la\n")
    f.write(f"put {test_file} {remote_file}\n")
    f.write(f"ls -la {remote_file}\n")
    f.write(f"get {remote_file} {os.path.join(SFTP_TEST_DIR, 'test_download.txt')}\n")
    f.write(f"rm {remote_file}\n")
    f.write(f"bye\n")

env = os.environ.copy()
env["SSH_ASKPASS"] = askpass_script
env["SSH_ASKPASS_REQUIRE"] = "force"
env["DISPLAY"] = ":0"

cmd = [
    "sftp",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=no",
    "-P", str(SFTP_PORT),
    "-b", batch_file,
    f"{USER}@{HOST}"
]

try:
    result = subprocess.run(
        cmd, env=env, capture_output=True, text=True, timeout=30
    )
    print("=== STDOUT ===")
    print(result.stdout)
    if result.stderr:
        print("=== STDERR ===")
        print(result.stderr)
    print(f"=== EXIT CODE: {result.returncode} ===")

    # Verify
    if os.path.exists(os.path.join(SFTP_TEST_DIR, "test_download.txt")):
        with open(os.path.join(SFTP_TEST_DIR, "test_download.txt")) as f:
            content = f.read()
        print(f"=== DOWNLOADED CONTENT ===\n{content}")

    # Check if upload happened
    if "test_sftp_upload.txt" in result.stdout:
        print("SFTP UPLOAD: OK")
    else:
        print("SFTP UPLOAD: FAILED")

    if "test_download.txt" in os.listdir(SFTP_TEST_DIR) if os.path.exists(SFTP_TEST_DIR) else False:
        print("SFTP DOWNLOAD: OK")
    else:
        print("SFTP DOWNLOAD: FAILED")

    if result.returncode == 0:
        print("SFTP TEST: PASSED")
        sys.exit(0)
    else:
        print("SFTP TEST: FAILED")
        sys.exit(1)
except subprocess.TimeoutExpired:
    print("SFTP TEST: TIMEOUT")
    sys.exit(1)
except Exception as e:
    print(f"SFTP TEST: ERROR - {e}")
    sys.exit(1)
