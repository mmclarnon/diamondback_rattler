import logging
import multiprocessing

from diamondback.domain import Command
from diamondback.action import call_before_decorator,Action
from diamondback.connection.ssh import SSHClientWrapped,ConnectionState
from diamondback.action.execute import detect_package_manager

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
            self.command = None

        if 'package' in kwargs:
            self.package = kwargs['package']
        else:
            self.package = None

    def execute_command_via_ssh( self ):
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
            self.logger.info(f"[{host}] Successfully connected, executing: {self.command}")

            c = self.lookup_command( self.command[0], 'ssh' )
            if not c:
                new_command         = Command( )
                new_command.service = self.get_connection_type()
                new_command.value   = self.command
                new_command.name    = self.command.split(" ")[0]

                self.session.add( new_command )
                self.session.commit( )

            r = self.get_connection().execute( self.command, sudo=True )
                
            if r['out']:
                self.logger.info(f"[{host}] Output:{r['out'][:200]}")  # Limit output length
            if r['err']:
                self.logger.error(f"[{host}] Error: {r['err']}")
        except Exception as e:
            self.logger.error(f"[{host}] Error: {str(e)}")

    @call_before_decorator
    def run( self ):
        self.logger.info(f"installing package on host {self.get_input()}...")
        if not self.get_connection().connection_state == ConnectionState.CONNECTED:
            self.logger.warning( "not connected to taget cannot install anything" )
        else:
            if self.get_connection_type() == "ssh":
                package_manager = detect_package_manager(self.get_connection().get_client())
                self.logger.info( package_manager['install_cmd'] )
                command = str(package_manager['install_cmd']).format( **self.variables )

                self.logger.info( f'command to execute-->{command}')

                if self.sudo:
                    self.command = f"sudo {command}"

                self.execute_command_via_ssh( )
            self.logger.info("installation completed on target")
        return self

class RemovePackage( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'removepkg' )
        self.logger.info( 'initializing REMOVE Package action' )

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )
    
        if "sudo" in kwargs:
            self.sudo = kwargs["sudo"]
        else:
            self.sudo = False

        if 'commands' in kwargs:
            self.command = kwargs['commands']
        else:
            self.command = None

        if 'package' in kwargs:
            self.package = kwargs['package']

    def execute_command_via_ssh( self ):
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
            self.logger.info(f"[{host}] Successfully connected, executing: {self.command}")

            c = self.lookup_command( self.command, 'ssh' )
            if not c:
                new_command         = Command( )
                new_command.service = self.get_connection_type()
                new_command.value   = self.command
                new_command.name    = self.command.split(" ")[0]

                self.session.add( new_command )
                self.session.commit( )

            r = self.get_connection().execute( self.command, sudo=True )
                
            if r['out']:
                self.logger.info(f"[{host}] Output:\n{r['out'][:200]}")  # Limit output length
            if r['err']:
                self.logger.error(f"[{host}] Error: {r['err']}")
        except Exception as e:
            self.logger.error(f"[{host}] Error: {str(e)}")

    @call_before_decorator
    def run( self ):
        self.logger.info(f"\REMOVING package on host {self.get_input()}...")
        
        if self.get_connection_type() == "ssh":
            package_manager = detect_package_manager(self.get_connection().get_client())
            command = package_manager['remove_cmd'].format(self.package)

            if self.sudo:
                self.command = f"sudo {command}"

            self.execute_command_via_ssh( self.package )

        self.logger.info("removal completed on target")
        return self