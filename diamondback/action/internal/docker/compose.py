import logging
import time

from diamondback.action import call_before_decorator,Action

class DockerCompose( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'dockercompose' )
        self.logger.info( 'initializing DockerCompose action' )

    @call_before_decorator
    def run( self ):
        self.logger.info(f"sleep for {self.get_input()} seconds")
        
        time.sleep( int(self.get_input()) )

        self.logger.info("sleep completed, moving on....")
        return self