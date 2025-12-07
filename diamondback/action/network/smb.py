import logging
import socket
from impacket.smbconnection import SMBConnection, SessionError
import socket

from diamondback.action import Action
from diamondback.domain import *

class SMBConnectionAttempt( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'smbconnectionattempt' )
        self.logger.info( 'initializing SMB Connection Attempt action' )

        i = self.get_input( )
        p = self.password
        u = self.username
        self.port = 445
        self.logger.info( f'using supplied target of {i}, username of {u}' )
    
    def check_smb_access(self, t, port=445, username=None, password=None):
        """
        Check if a host is alive and allows SMB connection on specified port.
        
        Args:
            t: Target host (IP address or hostname)
            port: Port number to check (typically 445 or 139)
            username: Optional username for authentication (default: None)
            password: Optional password for authentication (default: None)
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # Use empty strings if username/password are None for guest/anonymous attempt
            user = username if username is not None else ''
            pwd = password if password is not None else ''
            
            # Attempt to establish SMB connection
            # Using '*SMBSERVER' as remote name (generic placeholder)
            smb = SMBConnection(t, t, sess_port=port, timeout=5)
            
            # Try to login (guest/anonymous if no credentials provided)
            smb.login(user, pwd)
            
            # If we get here, connection was successful
            # Close the connection cleanly
            smb.logoff()
            
            return True
        except socket.timeout:
            # Host didn't respond in time
            return False
        except SessionError:
            return True
        except socket.error:
            # Network-related errors (connection refused, host unreachable, etc.)
            return False
        except Exception as e:
            # Any other exception (authentication failure, SMB protocol errors, etc.)
            # We still consider this as "not accessible" for our purposes
            self.logger.info( e )
            return False
        
    def run( self ):
        self.logger.info( 'starting SMB connection attempt action' )
        
        self.set_output( self.check_smb_access(self.get_input(), 445, self.username) )
        if self.does_host_exist(self.get_input()):
            host_record = self.lookup_host_by_address( self.get_input() )
        else:
            self.logger.info( f'host record did not exist, save new one for {self.get_input()}' )
            host_record                  = Target( )
            host_record.address          = self.get_input( )
            host_record.discovery_method = 'smb'

        if self.get_output( ):
            self.logger.info( 'this host has active SMB...' )
            self.get_session().add( host_record )

            smb_service           = TargetService( )
            smb_service.name      = self.get_service_for( self.port )
            smb_service.target_id = host_record.id
            smb_service.protocol  = 'tcp'

            self.session.add( smb_service )
            self.speak_text( f'connected to {self.get_input()} using SMB')

            self.captured_target = host_record

            host_record.os      = 'windows'
        else:
            self.logger.info( 'this host does not have active SMB' )

        self.get_session().commit( )
        self.logger.info( 'SMB connection attempt action completed....' )
        return self

