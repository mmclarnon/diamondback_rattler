import logging
import multiprocessing

from diamondback.domain import Command
from diamondback.action import call_before_decorator,Action
from diamondback.connection.ssh import SSHClientWrapped

class InstallPackage( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'installpkg' )
        self.logger.info( 'initializing Install Package action' )

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )
    
        if "sudo" in kwargs:
            self.sudo = kwargs["sudo"]
        else:
            self.sudo = False

        if 'commands' in kwargs:
            self.command = kwargs['commands']
        else:
            self.command = 'sudo apt install -y {package}'

        if 'package' in kwargs:
            self.package = kwargs['package']

            vars =  {
                        'package': self.package
                    }
            
            self.command = self.command.format( **vars )

    def execute_command_via_ssh(self, package):
        """
        Execute commands on a remote host via SSH.
        
        Args:
            host: IP address of the host
            username: SSH username
            password: SSH password
        """
        self.logger.info(f"\n[Process {multiprocessing.current_process().pid}] "
                f"Connecting to {self.get_input()}")
        host = self.get_input()
        try:
            # Create SSH client
            client = SSHClientWrapped( self.username, self.password, self.get_input(), 22 )
            
            self.logger.info(f"[{host}] Successfully connected, executing: {self.command}")

            c = self.lookup_command( self.command[0], 'ssh' )
            if not c:
                new_command         = Command( )
                new_command.service = 'ssh'
                new_command.value   = self.command
                new_command.name    = self.command.split(" ")[0]

                self.session.add( new_command )
                self.session.commit( )

            formatted_command = f'{self.command} {package}'

            r = client.execute( formatted_command, sudo=True )
                
            if r['out']:
                self.logger.info(f"[{host}] Output:\n{r['out'][:200]}")  # Limit output length
            if r['err']:
                self.logger.error(f"[{host}] Error: {r['err']}")
                            
            # Close connection
            client.close()
            self.logger.info(f"[{host}] Connection closed")
        except Exception as e:
            self.logger.error(f"[{host}] Error: {str(e)}")

    @call_before_decorator
    def run( self ):
        self.logger.info(f"\Installing package on host {self.get_input()}...")
        
        self.execute_command_via_ssh( self.package )

        self.logger.info("installation completed on target")
        return self