from abc import ABC, abstractmethod
from enum import Enum
import logging
import time
import traceback

import paramiko

DEFAULT_CONNECTION_TIMEOUT = 3

class ConnectionState( Enum ):
    CONNECTED = 1
    NOT_CONNECTED = 2
    ERROR = 3
    CLOSED = 4
    UNKNOWN = 5

class Connection(ABC):
    """
    the base class for all diamonback connection(s). this is designed for the 
    principal purpose of easing development of new features for training 
    purposes. 
    """
    def __init__( self, target_address, username=None, password=None, port=0 ):
        self.set_target( target_address )
        self.set_username( username )
        self.set_password( password )
        self.set_port( port )
        self.set_client( None )
        self.timestamp = 0
        self.connection_state = ConnectionState.UNKNOWN

        self.errors = []

    def get_errors( self ):
        return self.errors

    def is_connected( self ):
        return self.connection_state == ConnectionState.CONNECTED

    def set_connection_type( self, connection_type ):
        self.connection_type = connection_type
    
    def get_connection_type( self ):
        return self.connection_type
    
    def set_client( self, connection_client ):
        self.client = connection_client

    def get_client( self ):
        return self.client

    def set_target( self, target ):
        self.target = target

    def get_target( self ):
        return self.target

    def set_username( self, username ):
        self.username = username
    
    def set_password( self, password ):
        self.password = password

    def get_username( self ):
        return self.username

    def get_password( self ):
        return self.password

    def set_port( self, port ):
        self.port = port

    def get_port( self ):
        return self.port

    @abstractmethod
    def open(self):
        pass

    @abstractmethod
    def close(self):
        pass

class SSHConnection( Connection ):
    def __init__( self, target_address, username, password ):
        super().__init__( target_address,username, password )  # Call the abstract class's __init__
        self.logger = logging.getLogger( 'sshconnection' )
        self.set_connection_type( 'ssh' )
        self.set_port( 22 )

    def open( self ):
        ct = self.get_connection_type( )
        t = self.get_target()
        try:
            self.logger.info( f'opening {ct} connection to {t}' )
            # Create SSH client
            client = paramiko.SSHClient()
            client.load_system_host_keys( )
            client.set_missing_host_key_policy( paramiko.AutoAddPolicy() )
            
            # Attempt connection
            client.connect(
                hostname=self.get_target(),
                port=self.get_port(),
                username=self.get_username(),
                password=self.get_password(),
                timeout=DEFAULT_CONNECTION_TIMEOUT,
                allow_agent=False,
                look_for_keys=False
            )

            self.set_client( client )
            self.connection_state = ConnectionState.CONNECTED
            self.timestamp = time.time()

            self.logger.info( 'connection opened....' )
        except:
            self.get_errors().append( traceback.format_exc() )
            self.logger.error( 'ERROR: unable to open connection? check error logs' )
            self.connection_state = ConnectionState.ERROR

    def close( self ):
        t = self.get_target( )
        self.logger.info( 'closing connection to {t}' )

        self.get_client().close( )
        self.connection_state = ConnectionState.CLOSED
    
    def __del__( self ):
        self.logger.info( 'connection deconstructor firing..' )
        if self.connection_state != ConnectionState.CLOSED:
            try:
                if self.get_client():
                    self.logger.info( 'calling paramiko specific close() now' )
                    self.get_client().close( )
            except:
                self.logger.warning( 'quietly handling exception closing paramiko connection' )

            self.connection_state = ConnectionState.CLOSED
            self.logger.info( 'marking connection as closed.' )