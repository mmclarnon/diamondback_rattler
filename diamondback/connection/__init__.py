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

