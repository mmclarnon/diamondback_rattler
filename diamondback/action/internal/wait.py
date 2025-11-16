import logging
import time

from diamondback.action import call_before_decorator,Action

class Wait( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'sleep' )
        self.logger.info( 'initializing wait action' )

        self.default_wait = 3600
        self.wait_period  = 0
        
        if "wait" in kwargs:
            self.wait_period = int( kwargs['timeout'] )
        elif "sleep" in kwargs:
            self.wait_period = int( kwargs['sleep'] )
        else:
            self.wait_period = self.default_wait
        
        self.logger.info( f'waiting for {self.wait_period} seconds' )

    @call_before_decorator
    def run( self ):
        self.logger.info(f"waiting for CTRL-C OR {self.wait_period} seconds")
        
        starting_time = time.time( )
        current_time  = time.time( )
        while current_time < starting_time + self.wait_period:
            try:
                current_time = time.time( )
                time.sleep( 1 )
            except KeyboardInterrupt:
                self.logger.info("observed CTRL-C, moving on....")
                starting_time = time.time( )
                return self
        return self