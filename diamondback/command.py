import logging
from domain import Command

class ShellCommand:
    def __init__( self, syntax, *args, **kwargs ):
        self.syntax = syntax
    
        self.executable = syntax.split(" ")[0]

    def get_syntax( self ):
        return self.syntax
    
    def set_syntax( self, syntax ):
        self.syntax = syntax
    
    def convert_to_object( self ):
        c = Command( )

        return C