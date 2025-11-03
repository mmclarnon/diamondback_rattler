import pwncat

# Replace with your target's SSH credentials
host = "192.168.1.100"
port = 22
username = "targetuser"
password = "targetpassword"

# Create a pwncat SSH session
session = pwncat.connect(f"ssh://{username}:{password}@{host}:{port}")

# Run a shell command on the remote host
result = session.run("uname -a")
print("Remote system info:", result)

# Run another command
result = session.run("whoami")
print("Current user:", result)

# Close the session
session.close()
