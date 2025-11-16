#!/usr/bin/env python3
"""
Network SSH Discovery and Command Execution Tool

WARNING: This script should only be used on networks you own or have 
explicit permission to scan and access. Unauthorized network scanning 
and access attempts are illegal.
"""
import base64
import configparser
import nacl
from nacl import secret
import os
import click
from logging.config import dictConfig
import logging

import warnings
import sys

import threading

# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Add the parent directory (or any other relevant directory) to sys.path
# For example, to add the directory containing the current script:
sys.path.insert(0, os.path.dirname(script_dir)) 

from agent import *
from scapy.all import *

# Suppress Scapy warnings
conf.verb = 0

NAME = 'diamondback'
OUR_CONFIGURATION_FILE = "configuration.ini"

logging.config.fileConfig(OUR_CONFIGURATION_FILE)

CURRENT_DIRECTORY      = os.path.abspath( os.path.dirname(__file__) )
PARENT_DIRECTORY       = os.path.abspath( os.path.dirname(CURRENT_DIRECTORY) )
DATA_DIRECTORY         = os.path.join( PARENT_DIRECTORY, "data")
OPPLAN_DIRECTORY       = os.path.join( DATA_DIRECTORY, "operations")
VERSION_FILE           = "VERSION.txt"
STOP_EVENT             = threading.Event( )
logger                 = logging.getLogger( '{}'.format(NAME) )

# Suppress paramiko warnings for demo purposes
warnings.filterwarnings("ignore")
logging.getLogger("paramiko").setLevel(logging.WARNING)

def read_version():
   with open( os.path.join(PARENT_DIRECTORY,VERSION_FILE), 'r' ) as reader:
       return reader.read()

def read_properties( context ) -> configparser.ConfigParser:
    our_configuration = None
    full_path_to_project_config = context.obj['HOME'] + os.sep + context.obj['CONFIG']

    logger.info( "reading properties" )

    context.obj['CONFIGURATION_FILE'] = full_path_to_project_config
    logger.info( "full path to configuration file is {}".format(context.obj['CONFIGURATION_FILE']) )

    if os.path.exists(full_path_to_project_config):
        our_configuration = configparser.ConfigParser()        
        our_configuration.read( full_path_to_project_config )
        logger.debug( "all read" )
    return our_configuration

def save_encryption_key_to_file( ctx ):
    configuration  = ctx.obj['CONFIGURATION']
    encryption_key = configuration.get( 'security', 'encryption_key' )
    logger.info( 'saving encryption key to file {}'.format(encryption_key) )
    
    with open( encryption_key, 'w' ) as writer:
        writer.write( ctx.obj['KEY'].hex() )
        logger.debug( 'saved' )

def load_encryption_key( ctx ):
    """
    load the encryption key for sensitive properties from a local file. This is
    used for securing properties against local access.
    """
    configuration       = ctx.obj['CONFIGURATION']
    exec_name           = os.path.basename( sys.executable )
    full_path_to_binary = os.path.dirname( os.path.abspath(sys.executable) )
    encryption_key      = configuration.get( 'security', 'encryption_key' )
    full_path_to_key    = os.path.join(full_path_to_binary,encryption_key) 
    logger.info( 'attempting to load encryption key from {}'.format(encryption_key) )
    
    if not os.path.exists( encryption_key ):
        if not os.path.exists( full_path_to_key  ):
            logger.info( 'no encryption key found, generate new key?' )
            # This must be kept secret, this is the combination to your safe
            
            ctx.obj['KEY'] = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            logger.info( 'generated' )
            # This is your safe, you can use it to encrypt or decrypt messages
            ctx.obj['BOX'] = nacl.secret.SecretBox( ctx.obj['KEY'] )
            logger.info( 'generated box' )
            save_encryption_key_to_file( ctx )
        else:
            logger.info( 'reading from {}'.format(full_path_to_key) )
            with open( full_path_to_key, 'r' ) as reader:
                ctx.obj['KEY'] = bytes.fromhex( reader.read() )
                ctx.obj['BOX'] = nacl.secret.SecretBox( ctx.obj['KEY'] )
                logger.info( 'loaded key' )
                        
    else:
        logger.info( 'reading from {}'.format(encryption_key) )
        with open( encryption_key, 'r' ) as reader:
            ctx.obj['KEY'] = bytes.fromhex( reader.read() )
            ctx.obj['BOX'] = nacl.secret.SecretBox( ctx.obj['KEY'] )
            logger.info( 'loaded key' )

def save_configuration( ctx ):
    with open( ctx.obj['CONFIGURATION_FILE'], 'w' ) as writer:
        logger.info( 'save updated properties with last used values to {}'.format(ctx.obj['CONFIGURATION_FILE']) )
        ctx.obj['CONFIGURATION'].write( writer, space_around_delimiters=True )
    logger.info( 'done' )

    logger.info( 'reload configuration from disk' )
    ctx.obj['CONFIGURATION'] = read_properties( ctx )  

def is_base64(s: str) -> bool:
    """
    Checks if a string is Base64 encoded.

    Args:
        s: The string to check.

    Returns:
        True if the string is Base64 encoded, False otherwise.
    """
    try:
        base64.b64decode(s, validate=True)
        return True
    except base64.binascii.Error:
        return False
    
def read_password( ctx ):
    """
    attempt to read password from INI file and decrypt if possible. prevents
    someone from having to supply a password on the command line and having
    this be saved in shell history.
    """
    logger.info( 'read password from property file' )
    if ctx.obj['CONFIGURATION'].has_option( "security", "password" ):
        logger.info( 'found password' )
        password = ctx.obj['CONFIGURATION'].get( 'security', 'password', fallback=None )
        if password:
            if is_base64( password ):
                logger.info( 'decode password my dawg' )
                decoded_pass        = base64.b64decode( password )
                ctx.obj['PASSWORD'] = ctx.obj['BOX'].decrypt( decoded_pass ) 
        else:
            if not ctx.obj['PASSWORD']:
                raise AttributeError( 'no password value found?' )
    else:
        logger.warning( 'did not find a password setting?' )

@click.group()
@click.option( '-c', '--configuration' )
@click.option( '-q', '--quiet', is_flag=True )
@click.option( '-D', '--debug', is_flag=True )
@click.option( '-H', '--home' )
@click.option( '-l', "--light", is_flag=True)
@click.option( '-p', '--password' )
@click.option( '-t', '--target' )
@click.option( '-u', '--username' )
@click.pass_context
def diamondback_client(ctx, configuration, quiet, debug, home, light, password, target, username ):
    # ensure that ctx.obj exists and is a dict (in case `cli()` is called
    # by means other than the `if` block below)
    ctx.ensure_object( dict )
  
    ctx.obj['QUIET'] = quiet
    if quiet:
        logger.propagate = False      

    if not configuration:
        ctx.obj['CONFIG'] = OUR_CONFIGURATION_FILE
    else:
        ctx.obj['CONFIG'] = configuration
    
    logger.info( 'set path to properties file as {}'.format(ctx.obj['CONFIG']) )
        
    if debug:
        logging.getLogger().setLevel( logging.DEBUG )   
    
    ctx.obj["VERSION"] = read_version()

    if not home:
        ctx.obj["HOME"]    = PARENT_DIRECTORY
    else:
        ctx.obj["HOME"]    = home

    logger.info( '{} version {} startup'.format(NAME,ctx.obj['VERSION']) )
    ctx.obj['CONFIGURATION'] = read_properties( ctx )      
    logger.info( 'read properties' )

    load_encryption_key( ctx ) 

    if target:
        logger.info( 'set target to {}'.format(target) )
        ctx.obj['TARGET'] = target
    else:
        ctx.obj['TARGET'] = None
    
    if username:
        ctx.obj['USERNAME'] = username
    else:
        ctx.obj['USERNAME'] = ctx.obj['CONFIGURATION'].get('security','username')
        
    if password:
        logger.info( 'set password value' )
        ctx.obj['PASSWORD'] = password
        enc_pass            = base64.b64encode( ctx.obj['BOX'].encrypt(password.encode('utf-8')) ).decode('utf-8')
        ctx.obj['CONFIGURATION'].set( 'security', 'password', enc_pass )
        save_configuration( ctx )

        logger.info( 'updated properties password as {}'.format(enc_pass) )
    else:
        logger.info( 'attempting to set password from properties' )
        ctx.obj['PASSWORD'] = read_password(ctx)
        logger.info( ctx.obj['PASSWORD'])     

    ctx.obj['STOP_EVENT'] = threading.Event( ) 
    ctx.obj['DIRECTORY']  = os.path.abspath( sys.executable )

@diamondback_client.command(help="Simple helper to start operation for training")
@click.option( '-o', '--operation' )
@click.option('--network', '-n',
              help='Network range to scan (CIDR notation)')
@click.option('--commands', '-c', multiple=True,
              help='Commands to execute on discovered hosts')
@click.option('--skip-discovery', is_flag=True,
              help='Skip network discovery and use provided hosts')
@click.option('--hosts', multiple=True,
              help='Specific hosts to scan (if skip-discovery is set)')
@click.pass_context
def basic(ctx, operation, network, commands, skip_discovery, hosts):
    """
    basic functionality for the Diamondback Rattler malware. This should execute
    simple remote actions that a junior or entry-level analyst can spot with some 
    minor hand-holding. This should run until the user presses CTRL-C to cancel. 
    """
    if ctx.obj['CONFIGURATION']:
        logger.info( 'initialize diamondback instance with context' )
        d = Diamondback( ctx, skip_discovery=skip_discovery, hosts=hosts, network=network )
    else:
        logger.info( 'initialize diamondback with empty context' )
        d = Diamondback( None, skip_discovery=skip_discovery, hosts=hosts, network=network )

    if not operation:
        operation = "basic"

    path_to_opplan = os.path.join( OPPLAN_DIRECTORY, f"{operation}.json" )
    logger.info( f"attempting to open operational play {path_to_opplan}" )
    try:
        with open( path_to_opplan, "rb" ) as reader:
            opplan  = json.load( reader )
            logger.info( f"read operational plan {operation}" )
            d.set_operation_plan( opplan )
    except:
        logger.error( "unable to load this opplan?" )
        sys.exit( -1 )
    try:
        d.run( )
        return None
    except PermissionError:
        click.echo("\n❌ Error: This script requires root/administrator privileges "
                  "for network scanning.", err=True)
        click.echo("Please run with: sudo python script.py", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"\n❌ Unexpected error: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    # Check if running as root (required for scapy ARP scanning)
    if sys.platform != 'win32' and os.geteuid() != 0:
        click.echo("⚠️  This script requires root privileges for network scanning.")
        click.echo("Please run with: sudo python script.py")
        sys.exit(1)
    
    diamondback_client( obj={} )