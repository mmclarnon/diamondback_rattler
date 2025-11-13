import logging
import multiprocessing
import random
import time

from diamondback.action import call_before_decorator,Action
from connection.ssh import SSHClientWrapped
from domain import Command

class FileSystemAction( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'filesystemaction' )
        self.logger.info( 'initializing FileSystem action' )

        if "sudo" in kwargs:
            self.sudo = kwargs["sudo"]
        else:
            self.sudo = False

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )
    
        if 'remote_file' in kwargs:
            self.remote_file = kwargs['remote_file']
        else:
            self.remote_file = '/tmp/diamondback.tmp'