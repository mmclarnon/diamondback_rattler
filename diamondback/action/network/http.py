import logging

from diamondback.action import Action
from diamondback.domain import *

class HTTPGet( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'httpget' )
        self.logger.info( 'initializing HTTP GET action' )

        i = self.get_input( )
        p = self.password
        u = self.username
        self.logger.info( f'using supplied target of {i}, username of {u}, password of {p}' )
    
    def run( self ):
        self.logger.info( 'starting HTTP GET action' )

        # output = execute_command( "curl -fsSL https://get.docker.com -o get-docker.sh" )

        self.logger.info( 'ssh connection attempt action completed....' )
        return self

