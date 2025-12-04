import logging
import multiprocessing

from diamondback.domain import Command
from diamondback.action import call_before_decorator,Action
from diamondback.connection.ssh import SSHClientWrapped

class ExecuteCommand( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'executecmd' )
        self.logger.info( 'initializing ExecuteCommand action' )

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )
    
        if "sudo" in kwargs:
            self.sudo = kwargs["sudo"]
        else:
            self.sudo = False

        if 'command' in kwargs:
            self.original_command = kwargs['command']

            variables = self.variables | kwargs

            self.command = self.original_command.format( **variables )

        if 'background' in kwargs and kwargs['background']:
            if not self.command.endswith( "&" ):
                self.logger.info( 'appending ampersand "&" character to force command to background' )
                self.command = f"nohup {self.command} &"

    def execute_command( self ):
        """
        Execute commands on a remote host.
        
        Args:
            host: IP address of the host
            username: username
            password: password
        """
        self.logger.info(f"[Process {multiprocessing.current_process().pid}] Connecting to {self.get_input()}")
        host = self.get_input()
        try:
            self.logger.info(f"[{host}] Successfully connected, executing: '{self.command}'")

            c = self.lookup_command( self.command, self.get_connection_type() )
            if not c:
                new_command         = Command( )
                new_command.service = self.get_connection_type()
                new_command.value   = self.command
                new_command.name    = self.command.split(" ")[0]

                self.session.add( new_command )
                self.session.commit( )

            r = self.get_connection().execute( self.command, sudo=self.sudo )
            self.logger.info( f'execution completed--->{r}' )
            if 'out' in r:
                if r['out']:
                    self.logger.info(f"[{host}] Output:{r['out'][:200]}")  # Limit output length
                if r['err']:
                    self.logger.error(f"[{host}] Error: {r['err']}")
            else:
                self.logger.info( f"{r[:200]}" )  # Limit output length
        except Exception as e:
            self.logger.error(f"[{host}] Error: {str(e)}")

    @call_before_decorator
    def run( self ):
        self.logger.info(f"execute command on target {self.get_input()}...")
        
        self.execute_command( )

        self.logger.info("command execution completed on target")
        return self