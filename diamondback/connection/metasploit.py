import logging
import traceback

from pymetasploit3.msfrpc import MsfRpcClient

from domain import *
from diamondback.connection import *

class MetasploitRPCConnection( Connection ):
    def __init__( self, target_address, username=None, password=None ):
        super().__init__( target_address, username, password )  # Call the abstract class's __init__
        self.logger = logging.getLogger( 'msfrpcconnection' )
        self.set_connection_type( 'msfrpc' )
        self.set_port( 22 )

    def execute(self,command,sudo=False):
        raise NotImplementedError

    def open( self ):
        ct = self.get_connection_type( )
        t = self.get_target()
        try:
            self.logger.info( f'opening {ct} connection to {t}' )
            # MsfRpcClient automatically handles authentication
            self.set_client( MsfRpcClient(
                                            self.password,
                                            server=self.target,
                                            port=self.port,
                                            ssl=False 
                                        )
                            )
            self.connection_state = ConnectionState.CONNECTED
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

        self.get_client().core.stop( )
        self.connection_state = ConnectionState.CLOSED
        return self
    
    def get_client(self):
        return super().get_client().client

    def __del__( self ):
        self.logger.info( 'connection deconstructor firing..' )
        if self.connection_state != ConnectionState.CLOSED:
            try:
                if self.get_client():
                    self.logger.info( 'calling msf rpc specific close() now' )
                    self.get_client().core.stop( )
            except:
                self.logger.warning( 'quietly handling exception closing Metasploit RPC connection' )

            self.connection_state = ConnectionState.CLOSED
            self.logger.info( 'marking connection as closed.' )
