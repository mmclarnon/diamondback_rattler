import logging
import random
import time
import traceback

from diamondback.domain import *
from diamondback.connection import *

import pwncat
from pwncat.manager import Manager 

class PwncatConnection( Connection ):
    """
    
    """
    def __init__( self, target_address, username, password, key=None, sudo=True ):
        super().__init__( target_address, username, password )  # Call the abstract class's __init__
        self.logger = logging.getLogger( 'pwncatconnection' )
        self.set_connection_type( 'pwncat' )
        self.set_port( 22 )

        if key:
            self.logger.info("setup pwncat connection with ssh key-based authentication")
            self.key = key
        else:
            self.logger.info( 'setup pwncat connection wtih username/password' )
            self.key = None

    def set_manager( self, manager ):
        self.manager = manager
    
    def get_manager( self ):
        return self.manager

    def execute( self, command, sudo=False ):
        self.logger.info( "execute command on target using pwncat session" )
        result = self.get_client().platform.run(command, capture_output=True, text=True)
        return result

    def open( self ):
        """
        Connect to a target using an SSH direct connection.
        
        Args:
            target_ip (str): IP address of the target
            target_port (int): Port number of the bind shell (default: 22)
        """        
        ct = self.get_connection_type( )
        t = self.get_target()
        try:
            self.logger.info(f"[*] Attempting to connect to {self.target} as {self.username} using Pwncat(SSH)")

            # Create the SSH session
            self.session = self.manager.create_session(
                platform = "linux",
                host     = self.target,
                port     = self.port,
                user     = self.username,
                password = self.password,
                key      = self.key)  

            self.logger.info(f"[+] PWNCAT successfully connected to {self.target}:{self.port}")
            self.logger.info(f"[+] pwncat Session ID: {self.session.id}")
            
            # Get basic information about the target
            self.logger.info(f"[*] Target hostname: {self.session.platform}")
            self.logger.info(f"[*] Current user: {self.session.current_user()}")
            for d in self.session.platform.listdir(f'/home/{self.session.current_user().name}'):
                self.logger.info( d )
            
            # You can now interact with the session
            # For example, run commands:
            result = self.session.platform.run("whoami", capture_output=True, text=True)
            self.logger.info(f"[*] whoami output: {result.stdout.strip()}")
            self.connection_state = ConnectionState.CONNECTED
            self.client = self.session
            return self.session           
        except:
            tb = traceback.format_exc()
            self.logger.error( tb )
            self.get_errors().append( tb )
            self.logger.error( 'ERROR: unable to open connection? check error logs' )
            self.connection_state = ConnectionState.ERROR
        return self
    
    def close( self ):
        t = self.get_target( )
        self.logger.info( f'closing connection to {t}' )

        self.get_client().close( )
        self.connection_state = ConnectionState.CLOSED
        return self

    def __del__( self ):
        self.logger.info( 'connection deconstructor firing..' )
        if self.connection_state != ConnectionState.CLOSED:
            try:
                if self.get_client():
                    self.logger.info( 'calling pwncat specific close() now' )
                    self.get_client().close( )
            except:
                self.logger.warning( 'quietly handling exception closing pwncat connection' )

            self.connection_state = ConnectionState.CLOSED
            self.logger.info( 'marking connection as closed.' )
