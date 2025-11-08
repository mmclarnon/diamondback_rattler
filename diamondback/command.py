import logging
import shlex

from domain import Command

class ShellCommand:
    """
    Represents a command that will be executed by an operating specific shell 
    or connection such as WinRM or SSH. Allows me to write complex commands to
    be stored in a database or in JSON and recalled for execution by the Agent
    """
    def __init__( self, syntax, *args, **kwargs ):
        self.syntax = syntax
        self.tokens = shlex.split( self.get_syntax() )[1:]
        self.executable = syntax.split(" ")[0]
        self.variable_table = {}

    def get_syntax( self ):
        return self.syntax
    
    def set_syntax( self, syntax ):
        self.syntax = syntax
    
    def set_variable( self, name, key ):
        self.get_variables()[name] = key

    def get_variables( self ):
        return self.variable_table
    
    def __str__( self ):
        s = self.get_syntax().format( self.get_variables() )
        return f"{s}"

    def convert_to_object( self ):
        c = Command( )
        c.name = self.executable
        c.value = self.get_syntax()
        return c