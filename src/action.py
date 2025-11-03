import logging
import multiprocessing
from multiprocessing import Process
import random
import time

import paramiko
from scapy.all import ARP, Ether, srp

from support import *
from ssh import SSHClientWrapped

from domain import *

from mac_vendor_lookup import MacLookup

def set_variable_on_completion(variable_name, value):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
            finally:
                # Set the variable after the method completes, regardless of success or failure
                # This assumes the variable is accessible in the scope where the decorator is defined
                # For instance variables, you would need to pass the instance
                # For simplicity, we'll demonstrate with a global-like scope here
                globals()[variable_name] = value 
            return result
        return wrapper
    return decorator

class Action:
    def __init__( self, *args, **kwargs ):
        super().__init__( )  # Call parent's __init__
        if 'input' in kwargs:
            self.input = kwargs['input']
        else:
            self.input = None

        self.variables =    {
                                'name': 'action',
                                'start': time.time(),
                            }

        self.start_time = time.time() 

        if 'username' in kwargs:
            self.username = kwargs['username']
        else:
            self.username = None

        if 'session' in kwargs:
            self.session = kwargs['session']
        else:
            self.session = None

        if 'password' in kwargs:
            self.password = kwargs['password']
        else:
            self.password = None

        if 'target_address' in kwargs:
            self.target_address = kwargs['target_address']
            self.set_input( self.target_address )
        else:
            self.target_address = None

        self.output = None

    def add_variable( self, name, value ):
        self.variables['name'] = value

    def set_input( self, input ):
        self.input = input

    def get_input( self ):
        return self.input

    def get_output( self ):
        return self.output

    def set_output( self, output ):
        self.output = output

    def lookup_command( self, command, service ):
        self.logger.info( f'lookup command details for {command}' )
        return self.session.query( Command ).filter( Command.name == command, Command.service == service ).first( )        

    def get_commands_for( self, service ):
        self.logger.info( f'return all commands for {service}' )
        return self.session.query( Command ).filter( Command.service == service ).all( )

class ARPScan( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( *args, **kwargs )
        self.logger = logging.getLogger( 'arpscan' )
        self.logger.info( 'initializing ARPScan action' )

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )

    def discover_hosts_on_subnet( self, network_range=None, timeout=10 ):
        """
        Discover active hosts on the local subnet using ARP scan.
        
        Args:
            network_range: CIDR notation of the network to scan
            timeout: Timeout for ARP responses
        
        Returns:
            List of IP addresses of discovered hosts
        """
        if not network_range:
            network_range = self.get_input( )

        self.logger.info(f"Scanning network: {network_range}")
        
        # Create ARP packet
        arp    = ARP(pdst=network_range)
        ether  = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        # Send packet and receive responses
        result = srp(packet, timeout=timeout, verbose=True)[0]
        
        # Extract IP addresses from responses
        hosts = []
        for sent, received in result:
            hosts.append(received.psrc)

        self.set_output( hosts )
        self.logger.info( self.get_output() )
        
    def run( self ):
        self.logger.info( 'executing ARP Scan action to discover assets on target LAN' )
        self.discover_hosts_on_subnet( )
        self.logger.info( f'arp scan complete, found {len(self.get_output())} hosts' )

class SSHConnectionAttempt( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'sshconnection' )
        self.logger.info( 'initializing SSH Conection Attempt action' )

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )
    
    def check_ssh_access(self, port=22, timeout=3):
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
                hostname=self.get_input( ),
                port=port,
                username=self.username,
                password=self.password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False
            )

            transport = client.get_transport()
            self.banner = transport.get_banner()

            # Close connection
            client.close()
            return True
        except (paramiko.AuthenticationException, 
                paramiko.SSHException, 
                socket.timeout, 
                socket.error):
            return False

    def run( self ):
        self.logger.info( 'starting ssh connection attempt action' )
        
        self.set_output( self.check_ssh_access() )

        self.logger.info( 'ssh connection attempt action compelted....' )
        return self

class SSHCommandExecution( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'commandexec' )
        self.logger.info( 'initializing CmdExec action' )

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )
    
        if 'commands' in kwargs:
            self.commands = kwargs['commands']
        else:
            self.commands = [ 'whoami' ]

    def execute_commands_on_host(self, commands, port=22):
        """
        Execute commands on a remote host via SSH.
        
        Args:
            host: IP address of the host
            username: SSH username
            password: SSH password
            commands: List of commands to execute
            port: SSH port
        """
        self.logger.info(f"\n[Process {multiprocessing.current_process().pid}] "
                f"Connecting to {self.get_input()}")
        host = self.get_input()
        try:
            # Create SSH client
            client = SSHClientWrapped( self.username, self.password, self.get_input(), port )
            
            self.logger.info(f"[{host}] Successfully connected")
            
            # Execute each command
            for command in commands:
                self.logger.info(f"[{host}] Executing: {command}")

                c = self.lookup_command( command, 'ssh' )
                if not c:
                    new_command         = Command( )
                    new_command.service = 'ssh'
                    new_command.name    = command

                    self.session.add( new_command )
                    self.session.commit( )

                r = client.execute( command )
                
                if r['out']:
                    self.logger.info(f"[{host}] Output:\n{r['out'][:200]}")  # Limit output length
                if r['err']:
                    self.logger.error(f"[{host}] Error: {r['err']}")
                
                time.sleep(random.randint(1,3))  # Small delay between commands
            
            # Close connection
            client.close()
            self.logger.info(f"[{host}] Connection closed")
        except Exception as e:
            self.logger.error(f"[{host}] Error: {str(e)}")

    def run( self ):
        commands = self.commands
        # Step 3: Execute commands on SSH-accessible hosts using multiprocessing
        if commands:
            self.logger.info(f"\nExecuting commands on host {self.get_input()}...")
            self.logger.info(f"Commands to execute: {list(commands)}\n")
            
            # Create a process for each host
            processes = []
            process = multiprocessing.Process(
                target=self.execute_commands_on_host,
                args=(list(commands), 22)
            )
            process.start()
            processes.append(process)
            
            # Wait for all processes to complete
            for process in processes:
                process.join()
            
            self.logger.info("\n✓ Command execution completed on all hosts")