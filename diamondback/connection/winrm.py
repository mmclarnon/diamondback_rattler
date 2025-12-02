from io import StringIO
import logging
import os
import random
import socket
import time
import traceback
import winrm

from diamondback.domain import *
from diamondback.connection import *

class WinRMConnection( Connection ):
    def __init__( self, target_address, username, password, port=5985 ):
        super().__init__( target_address, username, password )  # Call the abstract class's __init__
        self.logger = logging.getLogger( 'winrmconnection' )
        self.set_connection_type( 'winrm' )
        self.set_port( port )

    def execute(self,command,sudo=False):
        command_parts = command.split(" ")
        return self.client.run_cmd(command_parts[0], command_parts[1:] )

    def open( self ):
        ct = self.get_connection_type( )
        t = self.get_target()
        try:
            self.logger.info( f'opening {ct} connection to {t} as {self.get_username()}' )
            #self.client = winrm.Session(self.get_target(), auth=(self.get_username(),self.get_password()))
            
            # Configure the WinRM session for HTTPS on port 5986
            self.client = winrm.Session(
                f'http://{self.get_target()}:{self.get_port()}/wsman',  # Endpoint URL with HTTPS and port 5986
                auth=(self.get_username(), self.get_password()),
                transport='basic',  # Or 'kerberos', 'credssp', 'certificate'
                server_cert_validation='ignore' # Use with caution, or configure trusted CA
            )

            self.logger.info( 'opened' )
            self.connection_state = ConnectionState.CONNECTED
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
                    self.logger.info( 'calling paramiko specific close() now' )
                    self.get_client().close( )

                if self.transport:
                    self.transport.close( )
            except:
                self.logger.warning( 'quietly handling exception closing paramiko connection' )

            self.connection_state = ConnectionState.CLOSED
            self.logger.info( 'marking connection as closed.' )
