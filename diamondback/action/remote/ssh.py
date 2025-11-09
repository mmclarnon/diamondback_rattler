import logging
import socket
import paramiko

from diamondback.action import Action
from diamondback.domain import *

class SSHConnectionAttempt( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'sshconnection' )
        self.logger.info( 'initializing SSH Conection Attempt action' )

        i = self.get_input( )
        p = self.password
        u = self.username
        self.logger.info( f'using supplied target of {i}, username of {u}, password of {p}' )
    
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
            client.close( )
            self.mark_successful( )
            return True
        except (paramiko.AuthenticationException, 
                paramiko.SSHException, 
                socket.timeout, 
                socket.error):
            return False

    def run( self ):
        self.logger.info( 'starting ssh connection attempt action' )
        
        self.set_output( self.check_ssh_access() )
        if self.does_host_exist(self.get_input()):
            host_record = self.lookup_host_by_address( self.get_input() )
        else:
            self.logger.info( f'host record did not exist, save new one for {self.get_input()}' )
            host_record         = Target( )
            host_record.address = self.get_input( )
            self.get_session().add( host_record )
            self.get_session().commit( )

        if self.get_output( ):
            self.logger.info( 'this host has ACTIVE ssh...' )
            ssh_banner = self.banner

            ssh_service          = TargetService( )
            ssh_service.name     = self.get_service_for( 22 )
            ssh_service.target_id= host_record.id
            ssh_service.protocol = 'tcp'
            ssh_service.banner   = ssh_banner

            self.session.add( ssh_service )
            self.session.commit()
            self.speak_text( f'connected to {self.get_input()} using SSH')
        else:
            self.logger.info( 'this host does not have active SSH' )

        self.logger.info( 'ssh connection attempt action completed....' )
        return self

