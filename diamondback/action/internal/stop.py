import logging

from diamondback.action import call_before_decorator,Action

class Stop( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'sleep' )
        self.logger.info( 'initializing stop action' )

        if 'stop_event' in kwargs:
            self.stop_event = kwargs['stop_event']

    @call_before_decorator
    def run( self ):
        self.logger.info(f"stopping agent now")

        self.stop_event.set( )

        return self
        