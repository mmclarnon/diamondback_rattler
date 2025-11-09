from io import StringIO
import logging
import os
import random
import socket
import time
import traceback
import paramiko

from action import Action
from domain import *
from diamondback.connection import *

class SSHClientWrapped:
    "A wrapper of paramiko.SSHClient"
    TIMEOUT = 4

    def __init__(   self, 
                    username   = None, 
                    password   = None, 
                    host       = None, 
                    port       = None, 
                    key        = None, 
                    passphrase = None, 
                    client     = None,
                    timeout    = 0 ):
        self.username = username
        self.password = password
        if client is None:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if key is not None:
                self.ssh_key = paramiko.RSAKey.from_private_key(StringIO(key), password=passphrase)
            else:
                self.ssh_key = None

            if timeout != 0:
                self.client.connect( host, port, username=username, password=password, pkey=key, timeout=timeout )
            else:
                self.client.connect( host, port, username=username, password=password, pkey=key )
        else:
            self.client = client

    def close( self ):
        if self.client is not None:
            self.client.close()
            self.client = None

    def execute( self, command, sudo=False ):
        feed_password = False
        if sudo and self.username != "root":
            command = "sudo -S -p '' %s" % command
            feed_password = self.password is not None and len(self.password) > 0
        stdin, stdout, stderr = self.client.exec_command(command)
        if feed_password:
            stdin.write(self.password + "\n")
            stdin.flush()
        return {'out': stdout.read(),
                'err': stderr.read(),
                'retval': stdout.channel.recv_exit_status()}

class SSHConnection( Connection ):
    def __init__( self, target_address, username, password, key=None ):
        super().__init__( target_address, username, password )  # Call the abstract class's __init__
        self.logger = logging.getLogger( 'sshconnection' )
        self.set_connection_type( 'ssh' )
        self.set_port( 22 )

        if key:
            self.logger.info("setup ssh connection with key-based authentication")
            self.key = key
        else:
            self.key = None

    def open( self ):
        ct = self.get_connection_type( )
        t = self.get_target()
        try:
            self.logger.info( f'opening {ct} connection to {t}' )
            # Create SSH client
            client = paramiko.SSHClient()
            client.load_system_host_keys( )
            client.set_missing_host_key_policy( paramiko.AutoAddPolicy() )
            
            if not self.key:
                self.logger( 'setup SSH connection with password authentication' )
                client.connect(
                    hostname=self.get_target(),
                    port=self.get_port(),
                    username=self.get_username(),
                    password=self.get_password(),
                    timeout=DEFAULT_CONNECTION_TIMEOUT,
                    allow_agent=False,
                    look_for_keys=False
                )
            else:
                self.logger.info( 'setup SSH connection with key-based authentication')
                if os.path.exists( self.key ):
                    self.logger.info( 'treating key as filename' )
                    # Attempt connection
                    client.connect(
                        hostname=self.get_target(),
                        port=self.get_port(),
                        username=self.get_username(),
                        key_filename=self.key,
                        timeout=DEFAULT_CONNECTION_TIMEOUT,
                        allow_agent=False,
                        look_for_keys=False
                    )   

            if self.client:
                transport = client.get_transport()
                transport.set_keepalive(interval=random.randint(45,75))

                self.set_client( client )
                self.connection_state = ConnectionState.CONNECTED
                self.timestamp = time.time()

                self.logger.info( 'connection opened....' )
            else:
                self.connection_state = ConnectionState.NOT_CONNECTED
                self.logger.error( "did not seem to create an SSH connection" )
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
