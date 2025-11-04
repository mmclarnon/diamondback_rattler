import paramiko
import pwncat
from pwncat.manager import Manager 
import time
import traceback
import sys

# === Configuration ===
target_host = "10.0.0.148"
target_port = 22
username = "sysadmin"
ssh_key_path = "/home/parallels/.ssh/id_rsa"  # Replace with your actual private key path
password = 'PASSWORD'
# Port on the target where socat will listen
remote_port = 4444

# SSL certificate and key paths (must exist on target)
remote_cert = "/tmp/target-cert.pem"
remote_key = "/tmp/target-key.pem"

# === Step 1: Connect to target via SSH using key ===
ssh_key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(target_host, port=target_port, username=username, password=password )

def connect_to_target( target_ip, target_port=8443, password=None ):
    """
    Connect to a target running a socat SSL encrypted bind shell.
    
    Args:
        target_ip (str): IP address of the target
        target_port (int): Port number of the bind shell (default: 4444)
    """
    # Create a pwncat manager instance
    with Manager() as manager:
        try:
            print(f"[*] Attempting to connect to {target_ip}:{target_port}")

            # Create the SSH session
            session = manager.create_session(
                platform="linux",
                host=target_ip,
                port=target_port,
                user=username,
                password=password
            )            

            print(f"[+] Successfully connected to {target_ip}:{target_port}")
            print(f"[+] Session ID: {session.id}")
            
            # Get basic information about the target
            print(f"[*] Target hostname: {session.platform}")
            print(f"[*] Current user: {session.current_user()}")
            for d in session.platform.listdir(f'/home/{session.current_user().name}'):
                print( d )
            
            # You can now interact with the session
            # For example, run commands:
            result = session.platform.run("whoami", capture_output=True, text=True)
            print(f"[*] whoami output: {result.stdout.strip()}")
        
            session.close()            
        except Exception as e:
            print( traceback.format_exc() )
            print(f"[-] Connection failed: {str(e)}", file=sys.stderr)
            sys.exit(1)

# === Step 5: Connect to the remote encrypted shell using pwncat ===
connect_to_target( target_host, target_port=22, password=password )

# === Step 7: Close session and SSH ===
ssh.close()
print("[*] Session closed.")
