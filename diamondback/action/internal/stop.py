import logging
import time

from diamondback.action import *

class Stop( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'sleep' )
        self.logger.info( 'initializing stop action' )

    @call_before_decorator
    def run( self ):
        self.logger.info(f"stopping agent now")

        return self
        