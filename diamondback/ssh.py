from io import StringIO
import socket
import paramiko
from concurrent.futures import ThreadPoolExecutor, as_completed

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
                key = paramiko.RSAKey.from_private_key(StringIO(key), password=passphrase)
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
