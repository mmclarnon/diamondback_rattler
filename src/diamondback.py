#!/usr/bin/env python3
"""
Network SSH Discovery and Command Execution Tool

WARNING: This script should only be used on networks you own or have 
explicit permission to scan and access. Unauthorized network scanning 
and access attempts are illegal.
"""
import base64
import configparser
import nacl
import os
import click
import paramiko
import socket
import multiprocessing
import logging
from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
import sys
import time

NAME = 'diamondback'
OUR_CONFIGURATION_FILE = "configuration.ini"

LOGGING_CONFIG = { 
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': { 
        'standard': { 
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': { 
        'default': { 
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',  # Default is stderr
        },
    },
    'loggers': { 
        '': {  # root logger
            'handlers': ['default'],
            'level': 'INFO',
            'propagate': False
        },
        '__main__': {  # if __name__ == '__main__'
            'handlers': ['default'],
            'level': 'DEBUG',
            'propagate': False
        },
    } 
}
logging.config.dictConfig(LOGGING_CONFIG)

CURRENT_DIRECTORY      = os.path.abspath( os.path.dirname(__file__) )
logger                 = logging.getLogger( '{}'.format(NAME) )

# Suppress paramiko warnings for demo purposes
warnings.filterwarnings("ignore")
logging.getLogger("paramiko").setLevel(logging.WARNING)

def read_properties( context ) -> configparser.ConfigParser:
    our_configuration = None
    full_path_to_project_config = context.obj['HOME'] + os.sep + context.obj['CONFIG']

    logger.info( "reading properties" )

    context.obj['CONFIGURATION_FILE'] = full_path_to_project_config
    logger.info( "full path to configuration file is {}".format(context.obj['CONFIGURATION_FILE']) )

    if os.path.exists(full_path_to_project_config):
        our_configuration = configparser.ConfigParser()        
        our_configuration.read( full_path_to_project_config )
        logger.debug( "all read" )
    return our_configuration

def save_encryption_key_to_file( ctx ):
    configuration  = ctx.obj['CONFIGURATION']
    encryption_key = configuration.get( 'security', 'encryption_key' )
    logger.info( 'saving encryption key to file {}'.format(encryption_key) )
    
    with open( encryption_key, 'w' ) as writer:
        writer.write( ctx.obj['KEY'].hex() )
        logger.debug( 'saved' )

def load_encryption_key( ctx ):
    """
    load the encryption key for sensitive properties from a local file. This is
    used for securing properties against local access.
    """
    configuration       = ctx.obj['CONFIGURATION']
    exec_name           = os.path.basename( sys.executable )
    full_path_to_binary = os.path.dirname( os.path.abspath(sys.executable) )
    encryption_key      = configuration.get( 'security', 'encryption_key' )
    full_path_to_key    = os.path.join(full_path_to_binary,encryption_key) 
    logger.info( 'attempting to load encryption key from {}'.format(encryption_key) )
    
    if not os.path.exists( encryption_key ):
        if not os.path.exists( full_path_to_key  ):
            logger.info( 'no encryption key found, generate new key?' )
            # This must be kept secret, this is the combination to your safe
            
            ctx.obj['KEY'] = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            logger.info( 'generated' )
            # This is your safe, you can use it to encrypt or decrypt messages
            ctx.obj['BOX'] = nacl.secret.SecretBox( ctx.obj['KEY'] )
            logger.info( 'generated box' )
            save_encryption_key_to_file( ctx )
        else:
            logger.info( 'reading from {}'.format(full_path_to_key) )
            with open( full_path_to_key, 'r' ) as reader:
                ctx.obj['KEY'] = bytes.fromhex( reader.read() )
                ctx.obj['BOX'] = nacl.secret.SecretBox( ctx.obj['KEY'] )
                logger.info( 'loaded key' )
                        
    else:
        logger.info( 'reading from {}'.format(encryption_key) )
        with open( encryption_key, 'r' ) as reader:
            ctx.obj['KEY'] = bytes.fromhex( reader.read() )
            ctx.obj['BOX'] = nacl.secret.SecretBox( ctx.obj['KEY'] )
            logger.info( 'loaded key' )

def save_configuration( ctx ):
    with open( ctx.obj['CONFIGURATION_FILE'], 'w' ) as writer:
        logger.info( 'save updated properties with last used values to {}'.format(ctx.obj['CONFIGURATION_FILE']) )
        ctx.obj['CONFIGURATION'].write( writer, space_around_delimiters=True )
    logger.info( 'done' )

    logger.info( 'reload configuration from disk' )
    ctx.obj['CONFIGURATION'] = read_properties( ctx )  

def discover_hosts_on_subnet(network_range="192.168.1.0/24", timeout=2):
    """
    Discover active hosts on the local subnet using ARP scan.
    
    Args:
        network_range: CIDR notation of the network to scan
        timeout: Timeout for ARP responses
    
    Returns:
        List of IP addresses of discovered hosts
    """
    click.echo(f"Scanning network: {network_range}")
    
    # Create ARP packet
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    # Send packet and receive responses
    result = srp(packet, timeout=timeout, verbose=0)[0]
    
    # Extract IP addresses from responses
    hosts = []
    for sent, received in result:
        hosts.append(received.psrc)
    
    click.echo(f"Discovered {len(hosts)} hosts on the network")
    return hosts

def check_ssh_access(host, username, password, port=22, timeout=3):
    """
    Check if SSH access is available with given credentials.
    
    Args:
        host: IP address of the host
        username: SSH username
        password: SSH password
        port: SSH port (default 22)
        timeout: Connection timeout
    
    Returns:
        True if SSH access successful, False otherwise
    """
    try:
        # Create SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Attempt connection
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
        
        # Close connection
        client.close()
        return True
        
    except (paramiko.AuthenticationException, 
            paramiko.SSHException, 
            socket.timeout, 
            socket.error):
        return False

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

@click.group()
@click.option( '-c', '--configuration' )
@click.option( '-q', '--quiet', is_flag=True )
@click.option( '-D', '--debug', is_flag=True )
@click.option( '-H', '--home' )
@click.option( '-l', "--light", is_flag=True)
@click.option( '-p', '--password' )
@click.option( '-t', '--target' )
@click.option( '-u', '--username' )
@click.pass_context
def diamondback_client(ctx, configuration, quiet, debug, home, light, password, target, username ):
    # ensure that ctx.obj exists and is a dict (in case `cli()` is called
    # by means other than the `if` block below)
    ctx.ensure_object( dict )
  
    ctx.obj['QUIET'] = quiet
    if quiet:
        logger.propagate = False      

    if not configuration:
        ctx.obj['CONFIG'] = OUR_CONFIGURATION_FILE
    else:
        ctx.obj['CONFIG'] = configuration
    
    logger.info( 'set path to properties file as {}'.format(ctx.obj['CONFIG']) )
        
    if debug:
        logging.getLogger().setLevel( logging.DEBUG )   
    
    
    logger.info( '{} version {} startup'.format(NAME,ctx.obj['VERSION']) )
    ctx.obj['CONFIGURATION'] = read_properties( ctx )      
    logger.info( 'read properties' )

    load_encryption_key( ctx ) 

    if target:
        logger.info( 'set target to {}'.format(target) )
        ctx.obj['TARGET'] = target
    else:
        ctx.obj['TARGET'] = None
    
    if username:
        ctx.obj['USERNAME'] = username
    else:
        ctx.obj['USERNAME'] = None
        
    if password:
        logger.info( 'set password value' )
        ctx.obj['PASSWORD'] = password
        enc_pass            = base64.b64encode( ctx.obj['BOX'].encrypt(password.encode('utf-8')) ).decode('utf-8')
        ctx.obj['CONFIGURATION'].set( 'security', 'password', enc_pass )
        save_configuration( ctx )

        logger.info( 'updated properties password as {}'.format(enc_pass) )

    ctx.obj['DIRECTORY'] = os.path.abspath( sys.executable )


@diamondback_client.command(help="Simple helper to start operation for training")
@click.option('--network', '-n', default='10.0.10.0/24', 
              help='Network range to scan (CIDR notation)')
@click.option('--username', '-u', default='sysadmin', 
              help='SSH username')
@click.option('--password', '-p', default='password', 
              help='SSH password')
@click.option('--commands', '-c', multiple=True, 
              default=['hostname', 'whoami', 'date', 'ps aux | head -5'],
              help='Commands to execute on discovered hosts')
@click.option('--port', default=22, 
              help='SSH port')
@click.option('--skip-discovery', is_flag=True,
              help='Skip network discovery and use provided hosts')
@click.option('--hosts', multiple=True,
              help='Specific hosts to scan (if skip-discovery is set)')
def basic(ctx, network, username, password, commands, port, skip_discovery, hosts):
    """
    Discover SSH-enabled hosts on local network and execute commands.
    
    WARNING: Only use on networks you own or have permission to scan!
    """
    
    click.echo("=" * 60)
    click.echo("SSH Network Discovery and Command Execution Tool")
    click.echo("=" * 60)
    click.echo("\n⚠️  WARNING: Only use on networks you own or have permission to scan!")
    click.echo("⚠️  Unauthorized access to computer systems is illegal!\n")
    
    # Confirm before proceeding
    if not click.confirm("Do you have permission to scan this network?"):
        click.echo("Exiting...")
        return
    
    try:
        # Step 1: Discover hosts on the network
        if skip_discovery:
            discovered_hosts = list(hosts)
            click.echo(f"Using provided hosts: {discovered_hosts}")
        else:
            discovered_hosts = discover_hosts_on_subnet(network)
            
            if not discovered_hosts:
                click.echo("No hosts discovered on the network.")
                return
        
        # Step 2: Check SSH access on discovered hosts
        ssh_hosts = scan_hosts_for_ssh(discovered_hosts, username, password)
        
        if not ssh_hosts:
            click.echo("\nNo hosts with SSH access found.")
            return
        
        click.echo(f"\n✓ Found {len(ssh_hosts)} hosts with SSH access:")
        for host in ssh_hosts:
            click.echo(f"  - {host}")
        
        # Step 3: Execute commands on SSH-accessible hosts using multiprocessing
        if commands and click.confirm("\nExecute commands on discovered hosts?"):
            click.echo(f"\nExecuting commands on {len(ssh_hosts)} hosts...")
            click.echo(f"Commands to execute: {list(commands)}\n")
            
            # Create a process for each host
            processes = []
            for host in ssh_hosts:
                process = multiprocessing.Process(
                    target=execute_commands_on_host,
                    args=(host, username, password, list(commands), port)
                )
                process.start()
                processes.append(process)
            
            # Wait for all processes to complete
            for process in processes:
                process.join()
            
            click.echo("\n✓ Command execution completed on all hosts")
        
        # Return the list of SSH-accessible hosts
        click.echo(f"\n📋 Summary: {len(ssh_hosts)} accessible hosts found")
        return ssh_hosts
        
    except PermissionError:
        click.echo("\n❌ Error: This script requires root/administrator privileges "
                  "for network scanning.", err=True)
        click.echo("Please run with: sudo python script.py", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"\n❌ Unexpected error: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    # Check if running as root (required for scapy ARP scanning)
    if sys.platform != 'win32' and os.geteuid() != 0:
        click.echo("⚠️  This script requires root privileges for network scanning.")
        click.echo("Please run with: sudo python script.py")
        sys.exit(1)
    
    diamondback_client( obj={} )