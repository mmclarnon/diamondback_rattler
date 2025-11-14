import logging
from multiprocessing import Process
import sys
import time

import numpy as np
import sounddevice as sd
import paramiko
from piper import PiperVoice
from piper.voice import PiperVoice

from connection import Connection
from connection.ssh import SSHConnection
from support import *
from domain import *

from util.timeout import exit_after

__all__ = ['Action', 'factory']

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

def call_before_decorator(func):
    """
    A decorator that calls a specific method (e.g., 'initialize') 
    of the class instance before running the decorated method.
    """
    def wrapper(self, *args, **kwargs):
        # The 'self' argument gives access to the class instance and its methods
        self.open_connection( )
        logging.debug(f"--- ACTION: Calling method automatically before '{func.__name__}' ---")
        self.save_platform_action()  # Call the "before" method
        result = func(self, *args, **kwargs) # Call the original method
        logging.debug(f"--- Decorator: '{func.__name__}' finished ---")
        return result
    return wrapper

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
        self.banner = None
        self.connection = None
        self.connection_type = "local"
        self.start_time = time.time() 
        self.variables =    {
                                'name': 'action',
                                'start': self.start_time,
                            }
        
        self.variables = self.variables | kwargs
        
        if 'skip' in kwargs:
            self._should_skip = kwargs['skip']
        else:
            self._should_skip = False

        if 'name' in kwargs:
            self.name = kwargs['name']
        else:
            self.name = self.__class__.__name__.lower()

        if "connection" in kwargs:
            self.connection_type = kwargs["connection"]
            self.connection = None

        if "configuration" in kwargs:
            self.configuration = kwargs["configuration"]

        if "context" in kwargs:
            self.context = kwargs["context"]

        if "location" in kwargs:
            self.location = kwargs["location"]

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

        if "key" in kwargs:
            self.key = kwargs["key"]
        else:
            self.key = None

        if 'target_address' in kwargs:
            if 'input' not in kwargs:
                self.target_address = kwargs['target_address']
                self.set_input( self.target_address )
                self.variables['target'] = self.target_address
            else:
                self.set_input( kwargs['input'] )
        else:
            self.target_address = None

        self.success = False
        self.output = None

        voicedir = self.configuration.get( 'piper', 'home' ) #Where onnx model files are stored on my machine
        model = os.path.join( voicedir, self.configuration.get('piper','voice') )
        self.speech_voice = PiperVoice.load(model)

        # set the file name depending on the operating system
        if sys.platform == 'win32':
            file = os.environ.get('WINDIR', r'C:\WINDOWS') + r'\system32\drivers\etc\services'
        else:
            file = '/etc/services'

        # Create an empty dictionary
        self.network_services = dict()

        # Iterate through the file, one line at a time
        for line in open(file):

            if line[0:1] != '#' and not line.isspace():
                k = line.split(None, )[1]

                # Extract the port number from port/protocol
                v = line.split('/', )[0]
                j = ''.join([i for i in v if not i.isdigit()])
                l = j.strip('\t')
                self.network_services[k] = l

    def should_skip( self ):
        return self._should_skip

    def set_connection_type( self, connection_type ):
        self.connection_type = connection_type

    def get_connection_type( self ):
        return self.connection_type

    def get_name( self ):
        return self.name

    def set_connection( self, connection ):
        self.connection = connection
    
    def get_connection( self ) -> Connection:
        return self.connection

    def speak_text( self, text_to_read, configuration=None ):
        audio_chunks = []
        if not configuration:
            configuration = self.configuration

        if configuration.getboolean('execution','speak'):
            if text_to_read.find( '.' ) != -1:
                text_to_read = text_to_read.replace( '.', ' dot ' )

            for audio_chunk in self.speech_voice.synthesize(text_to_read):
                # AudioChunk has .audio_int16_array property that returns numpy array
                audio_chunks.append(audio_chunk.audio_int16_array)
            
            audio_data = np.concatenate(audio_chunks)
            sd.play(audio_data, samplerate=self.speech_voice.config.sample_rate)
            sd.wait()

    def set_network_services( self, services ):
        self.network_services = services

    def get_service_for( self, port, protocol='tcp' ):
        try:
            return self.network_services[f'{port}/{protocol}']
        except:
            return None

    def get_location( self ):
        return self.location

    def mark_successful( self ):
        self.success = True

    def was_successful( self ):
        return self.success

    def add_variable( self, name, value ):
        self.variables['name'] = value

    def get_session( self ):
        return self.session

    def set_session( self, session ):
        self.session = session

    def set_input( self, input ):
        self.input = input

    def get_input( self ):
        return self.input

    def get_output( self ):
        return self.output

    def set_output( self, output ):
        self.output = output

    @exit_after(10)
    def lookup_command( self, command, service ):
        self.logger.info( f'lookup command details for {command}' )
        return self.session.query( Command ).filter( Command.name == command, Command.service == service ).first( )        

    def get_commands_for( self, service ):
        self.logger.info( f'return all commands for {service}' )
        return self.session.query( Command ).filter( Command.service == service ).all( )
    
    def save_platform_action( self ):
        self.logger.info( "save record of this platform action please")
        action_event       = PlatformAction( )
        action_event.name  = self.__class__.__name__
        action_event.input = self.get_input( )
        action_event.location = self.get_location()
        self.session.add( action_event )

        self.session.commit( )

    def lookup_host_by_address( self, address ):
        self.logger.info( f'lookup host {address}' )
        return self.session.query( Target ).filter( Target.address == address ).first( )

    def does_host_exist( self, target ):
        h = self.session.query( Target ).filter( Target.address == target ).exists( )

    def save_target( self, target ):
        new_target = Target( )

        new_target.address = target
        self.session.add( new_target )
        self.session.commit( )
        return new_target

    def open_connection( self ):
        self.logger.info( f"opening connection of type {self.connection_type}" )
        if self.connection_type.lower() == "ssh":
            self.connection = SSHConnection( self.get_input(), self.username, self.password, self.key ).open()