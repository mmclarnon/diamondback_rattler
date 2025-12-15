from abc import ABC, abstractmethod
from enum import Enum
import logging

from diamondback import load_all_modules_pkgutil,load_all_modules_simple,setup_lazy_loading,ModuleLoader,_classes,_functions,_modules

DEFAULT_CONNECTION_TIMEOUT = 3

class ConnectionState( Enum ):
    CONNECTED = 1
    NOT_CONNECTED = 2
    ERROR = 3
    CLOSED = 4
    UNKNOWN = 5

# Configure logging
logger = logging.getLogger(__name__)

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
        self.transport = None
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
        return self.connection_type.lower()
    
    def set_client( self, connection_client ):
        self.client = connection_client

    def get_client( self ):
        return self.client
    
    def put_file( self, local_path=None, remote_path=None ):
        raise NotImplementedError( )
    
    def get_file( self, remote_path=None, local_path=None ):
        raise NotImplementedError( )

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

    @abstractmethod
    def execute( self, command, sudo=False ):
        pass

# Option 5: Conditional loading based on environment
def initialize():
    """
    Initialize module loading based on environment variables.
    """
    import os
    
    load_strategy = os.getenv('MODULE_LOAD_STRATEGY', 'advanced')
    
    if load_strategy == 'simple':
        load_all_modules_simple()
    elif load_strategy == 'lazy':
        setup_lazy_loading()
    elif load_strategy == 'advanced':
        loader = ModuleLoader(
            recursive=True,
            auto_register=True,
            exclude_patterns=['test_*', '*_test.py', 'example_*']
        )
        results = loader.load_all()
        
        # Log results
        if results['errors']:
            logger.warning(f"Failed to load {len(results['errors'])} modules")
        
        logger.info(
            f"Successfully loaded: "
            f"{results['stats']['loaded_modules']} modules, "
            f"{results['stats']['loaded_classes']} classes, "
            f"{results['stats']['loaded_functions']} functions"
        )
    else:
        load_all_modules_pkgutil()
    
    # Build __all__ for star imports
    global __all__
    __all__ = list(_classes.keys()) + list(_functions.keys())


