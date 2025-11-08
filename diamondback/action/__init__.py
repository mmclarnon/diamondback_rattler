from multiprocessing import Process
import time
from support import *

from domain import *

def set_variable_on_completion(variable_name, value):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
            finally:
                # Set the variable after the method completes, regardless of success or failure
                # This assumes the variable is accessible in the scope where the decorator is defined
                # For instance variables, you would need to pass the instance
                # For simplicity, we'll demonstrate with a global-like scope here
                globals()[variable_name] = value 
            return result
        return wrapper
    return decorator

class Action:
    """
    The base class of all things done to a student machine or VM by the agent.
    The principal purpose of the action is to allow me to encode things I want
    the agent to do as JSON and then interpret them live in the agent. Anything
    that you want to track across multiple actions (e.g. start time) should be 
    defined in the base class here and use an accessor/mutator method to report
    from a child.
    """
    def __init__( self, *args, **kwargs ):
        super().__init__( )  # Call parent's __init__
        if 'input' in kwargs:
            self.input = kwargs['input']
        else:
            self.input = None

        self.start_time = time.time() 
        self.variables =    {
                                'name': 'action',
                                'start': self.start_time,
                            }

        if 'username' in kwargs:
            self.username = kwargs['username']
            self.variables['username'] = self.username
        else:
            self.username = None

        if 'session' in kwargs:
            self.session = kwargs['session']
        else:
            self.session = None

        if 'password' in kwargs:
            self.password = kwargs['password']
            self.variables['password'] = kwargs['password']
        else:
            self.password = None

        if 'target_address' in kwargs:
            self.target_address = kwargs['target_address']
            self.set_input( self.target_address )
            self.variables['target'] = self.target_address
        else:
            self.target_address = None

        self.success = False
        self.output = None

    def mark_successful( self ):
        self.success = True

    def was_successful( self ):
        return self.success

    def add_variable( self, name, value ):
        self.variables['name'] = value

    def set_input( self, input ):
        self.input = input

    def get_input( self ):
        return self.input

    def get_output( self ):
        return self.output

    def set_output( self, output ):
        self.output = output

    def lookup_command( self, command, service ):
        self.logger.info( f'lookup command details for {command}' )
        return self.session.query( Command ).filter( Command.name == command, Command.service == service ).first( )        

    def get_commands_for( self, service ):
        self.logger.info( f'return all commands for {service}' )
        return self.session.query( Command ).filter( Command.service == service ).all( )

