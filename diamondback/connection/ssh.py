from io import StringIO
import logging
import os
import random
import socket
import time
import traceback
import paramiko

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

    def get_transport( self ):
        return self.client.get_transport()

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
    def __init__( self, target_address, username, password, key=None, sudo=True ):
        super().__init__( target_address, username, password )  # Call the abstract class's __init__
        self.logger = logging.getLogger( 'sshconnection' )
        self.set_connection_type( 'ssh' )
        self.set_port( 22 )

        if key:
            self.logger.info("setup ssh connection with key-based authentication")
            self.key = key
        else:
            self.key = None

    def execute(self,command,sudo=False):
        return self.client.execute(command,sudo)

    def open( self ):
        ct = self.get_connection_type( )
        t = self.get_target()
        try:
            self.logger.info( f'opening {ct} connection to {t}' )
            # Create SSH client
            client = SSHClientWrapped(  self.get_username(), 
                                        self.get_password(), 
                                        t, 
                                        self.get_port(),
                                        self.key )

            if client:
                self.transport = client.get_transport()
                self.transport.set_keepalive(interval=random.randint(45,75))

                self.set_client( client )
                self.connection_state = ConnectionState.CONNECTED
                self.timestamp = time.time()

                self.logger.info( 'connection opened....' )
            else:
                self.connection_state = ConnectionState.NOT_CONNECTED
                self.logger.error( "did not seem to create an SSH connection" )
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
    
    def get_client(self):
        return super().get_client().client

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
