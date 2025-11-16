import logging
import multiprocessing
import os
import random
import time

from diamondback.action import call_before_decorator,Action
from diamondback.connection import Connection,ConnectionState
from diamondback.action.filesystem import *
from connection.ssh import SSHConnection,SSHClientWrapped
from domain import Command

class FileSystemWrite( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'filesystemwriteaction' )
        self.logger.info( 'initializing FileSystem WRITE action' )

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

        self.mode = 'keep'
        if 'mode' in kwargs:
            self.mode = kwargs['mode'].lower()
    
    def set_mode( self, mode ):
        self.mode = mode
    
    def get_mode( self ):
        return self.mode

    @call_before_decorator
    def run( self ):
        self.logger.info( "perform filesystem WRITE action" )

        if self.get_connection().connection_state == ConnectionState.CONNECTED:
            if self.get_connection_type() == "ssh":
                ssh_client = self.get_connection().get_client()

                does_file_exist = check_remote_file_exists( ssh_client, self.remote_file )

                if 'contents' in self.variables and self.variables['contents']:
                    self.logger.info( 'writing data to remote file' )
                    if not does_file_exist or self.mode == 'overwrite':
                        self.logger.info( 'remote file does not exist, go ahead and write to it now' )
                        write_to_remote_file(   ssh_client, 
                                                self.remote_file, 
                                                self.variables['contents'] )
                    else:
                        if self.mode == 'keep':
                            counter = 1
                            while does_file_exist and counter < 250:
                                new_filename = f"{self.remote_file}.{counter}"
                                does_file_exist = check_remote_file_exists( ssh_client, new_filename )
                                counter += 1
                            self.logger.info( f'found new filename {new_filename}' )
                            write_to_remote_file( ssh_client, new_filename, self.variables['contents'] )
                            self.logger.info( 'writing partial contents completed...')
                        elif self.mode == 'append':
                            self.logger.info( 'append to an existing file!!' )
                            write_to_remote_file( ssh_client, new_filename, self.variables['contents'], True )

                if 'local_file' in self.variables and self.variables['local_file']:
                    if os.path.exists( self.variables['local_file'] ):
                        self.logger.info( 'copy local file to remote path?' )
                        sftp_upload_simple(ssh_client, 
                                           self.variables['local_file'] , 
                                           self.remote_file) 