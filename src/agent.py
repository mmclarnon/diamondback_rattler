import logging
import os
import threading
import time

import cpuinfo
import psutil

from connection import *
from action import *
from support import *

class Client:
    def __init__( self, context=None, stop_event=None, hosts=None ):
        self.context            = context
        self.startup_time       = time.time( )
        self.cpu_info           = cpuinfo.get_cpu_info()
        self.available_memory   = int(psutil.virtual_memory()[0]/1024)/1024
        self.set_hosts( hosts )

        if not context:
            self.path_to_configuration    = os.path.join( PARENT_DIRECTORY, DEFAULT_CONFIGURATION_FILE )
            self.configuration = read_properties( self.path_to_configuration )
            self.context = None
        else:
            self.configuration = self.context.obj['CONFIGURATION']

        self.stop_event = stop_event

        self.actions_log = []

    def get_username( self ):
        if self.context and self.context.obj:
            return self.context.obj['USERNAME']
    
    def get_password( self ):
        if self.context and self.context.obj:
            return self.context.obj['PASSWORD']

    def add_action( self, action ):
        self.actions_log.append( action )

    def set_hosts( self, hosts ):
        self.hosts = hosts
    
    def  get_hosts( self ):
        return self.hosts

    def set_stop_event( self, event ):
        self.stop_event = event
    
    def get_stop_event( self ) -> threading.Event:
        return self.stop_event

    def get_startup_time( self ):
        return self.startup_time

class Diamondback( Client ):
    def __init__( self, context=None, stop_event=None, skip_discovery=False, hosts=None ):
        super().__init__( context, stop_event=stop_event, hosts=hosts )
        self.logger = logging.getLogger( 'diamondback' )

        self.skip_discovery = skip_discovery

        self.logger.info( 'initialized diamondback training agent...' )
    
    def run( self ):
        self.logger.info( 'starting agent' )

        if not self.skip_discovery:
            a = ARPScan( )
            a.start( )
            a.join( )
            self.logger.info( 'arp scan completed...' )
            self.logger.info( a.get_output() )
            self.set_hosts( a.get_output() )
        else:
            self.logger.info( f'explicitly setting hosts to {self.get_hosts()}' )

        while not self.get_stop_event( ).is_set( ):
            valid_targets     = []
            valid_ssh_targets = []

            self.logger.info( 'event loop execute, disregard previous output(s)' )

            if not self.skip_discovery:
                self.logger.info( '(re)discover live hosts on LAN')
                a = ARPScan( )
                a.start( )
                a.join( )
                self.logger.info( 'arp scan completed...' )
                self.logger.info( a.get_output() )
                self.set_hosts( a.get_output() )            

            self.logger.info( 'check for SSH targets' )
            for h in self.get_hosts( ):
                self.logger.info( f'checking {h} for SSH' )
                a = SSHConnectionAttempt( h, username=self.get_username(), password=self.get_password() )
                a.start( )
                a.join( )
                self.logger.info( 'SSH connection attempt complete' )
                if a.get_output( ):
                    self.logger.info( 'this host has ACTIVE ssh...' )
                    valid_ssh_targets.append( a )
                else:
                    self.logger.info( 'this host does not have active SSH' )

            valid_targets += valid_ssh_targets

            self.logger.info( f"\n✓ Found {len(valid_ssh_targets)} active hosts SSH access:" )
            for host in valid_ssh_targets:
                self.logger.info(f"  - {host}")
                        
            time.sleep( 5 )
