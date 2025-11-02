import socket
import paramiko
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_hosts_for_ssh(hosts, username, password):
    """
    Scan hosts for SSH access with given credentials.
    
    Args:
        hosts: List of IP addresses to scan
        username: SSH username
        password: SSH password
    
    Returns:
        List of IP addresses with successful SSH access
    """
    accessible_hosts = []
    
    click.echo(f"\nChecking SSH access on {len(hosts)} hosts...")
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        # Submit all tasks
        future_to_host = {
            executor.submit(check_ssh_access, host, username, password): host 
            for host in hosts
        }
        
        # Process results as they complete
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                if future.result():
                    accessible_hosts.append(host)
                    click.echo(f"✓ SSH access successful: {host}")
                else:
                    click.echo(f"✗ SSH access failed: {host}")
            except Exception as e:
                click.echo(f"✗ Error checking {host}: {str(e)}", err=True)
    
    return accessible_hosts

def execute_commands_on_host(host, username, password, commands, port=22):
    """
    Execute commands on a remote host via SSH.
    
    Args:
        host: IP address of the host
        username: SSH username
        password: SSH password
        commands: List of commands to execute
        port: SSH port
    """
    click.echo(f"\n[Process {multiprocessing.current_process().pid}] "
               f"Connecting to {host}")
    
    try:
        # Create SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to host
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=5,
            allow_agent=False,
            look_for_keys=False
        )
        
        click.echo(f"[{host}] Successfully connected")
        
        # Execute each command
        for command in commands:
            click.echo(f"[{host}] Executing: {command}")
            
            stdin, stdout, stderr = client.exec_command(command)
            
            # Read output
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            
            if output:
                click.echo(f"[{host}] Output:\n{output[:200]}")  # Limit output length
            if error:
                click.echo(f"[{host}] Error: {error}", err=True)
            
            time.sleep(0.5)  # Small delay between commands
        
        # Close connection
        client.close()
        click.echo(f"[{host}] Connection closed")
        
    except Exception as e:
        click.echo(f"[{host}] Error: {str(e)}", err=True)
