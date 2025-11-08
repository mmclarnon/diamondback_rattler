import copy
import glob
import logging
import multiprocessing
import os
import sys
import threading
import time
import traceback

import cpuinfo
import psutil

from sqlalchemy import create_engine
from sqlalchemy import desc
from sqlalchemy.ext.declarative import declarative_base  
from sqlalchemy.orm import sessionmaker, backref, Session

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Table
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session
from typing import List, Optional

import pwncat
from pwncat.manager import Manager 

import numpy as np
import sounddevice as sd
from piper import PiperVoice

from connection import *
from connection.ssh import *
from action import *
from action.scan.arp import ARPScan
from action.scan.icmp import ICMPScan
from action.internal.wait import Sleep
from action.execute import SSHCommandExecution
from support import *
from domain import *
from history_meta import versioned_session
from piper.voice import PiperVoice

import requests
import json
from datetime import datetime
from typing import Dict, Optional

ALLOWED_DATA_FILES =    [
                            'credential.json'
                        ]
DATA_DIRECTORY = os.path.join( os.path.abspath(os.path.dirname(os.path.dirname(__file__))), 'data' )
class Client:
    def __init__( self, context=None, stop_event=None, hosts=None, network=None ):
        self.context            = context
        self.startup_time       = time.time( )
        self.cpu_info           = cpuinfo.get_cpu_info()
        self.available_memory   = int(psutil.virtual_memory()[0]/1024)/1024
        self.logger = logging.getLogger( 'client' )

        if hosts:
            self.set_hosts( hosts.split(",") )
        else:
            self.set_hosts( [] )

        self.targets = {}

        if network:
            logging.info( f'set network address to {network}' )
            self.set_network( network )
        else:
            self.set_network( None )

        self.path_to_configuration    = os.path.join( PARENT_DIRECTORY, DEFAULT_CONFIGURATION_FILE )

        if not context:
            self.configuration = read_properties( self.path_to_configuration )
            self.context = None
        else:
            self.configuration = self.context.obj['CONFIGURATION']

        self.configuration_serial = copy.copy( self.configuration.getint('general','serial') ) 

        if not stop_event:
            self.stop_event = threading.Event( )
        else:
            self.stop_event = stop_event
        # Create queue for return value
        self.action_results = multiprocessing.Queue()

        database                   = self.configuration.get( 'database', 'url' )
        database_type              = self.configuration.get( 'database', 'type' )
        try:
            username                   = self.configuration.get( 'database', 'username' )
            hostname                   = self.configuration.get( 'database', 'host' )
            password                   = self.configuration.get( 'database', 'password' )
        except:
            pass

        self.engine = create_engine( f"{database_type}:///{database}", connect_args={"check_same_thread": False} )
        Session = sessionmaker( self.engine )  

        # Wrap your session inside a versioned_session
        versioned_session(Session)            
        self.session = Session( )

        # Create all tables
        print("Creating database schema...")
        Base.metadata.create_all(self.engine)
        
        self.actions_log    = []

        self.pwncat_manager = Manager()

        voicedir = self.configuration.get( 'piper', 'home' ) #Where onnx model files are stored on my machine
        model = os.path.join( voicedir, self.configuration.get('piper','voice') )
        self.speech_voice = PiperVoice.load(model)

        self.load_data(  )

    def load_data( self ):
        self.logger.info( 'loading operational data' )
        for f in glob.glob( os.path.join(DATA_DIRECTORY, "*.json") ):
            if os.path.basename(f) in ALLOWED_DATA_FILES:
                self.logger.info(f)
                t = os.path.basename(f).split(".")[0]
                f = os.path.join( DATA_DIRECTORY, f )
                self.logger.info( f"examining {f}" )
                with open( f, 'r' ) as reader:
                    data = json.load(reader)
                    if t.lower() == "credential":
                        self.logger.info( "parsing credentials" )

    def set_targets( self, targets ):
        self.targets = targets

    def get_targets( self ):
        return self.targets
    
    def add_target( self, key, target_object ):
        self.get_targets()[key] = target_object

    def set_network( self, network ):
        self.network = network

    def get_network( self ):
        return self.network

    def get_pwncat_manager( self ):
        return self.pwncat_manager

    def get_username( self ):
        if self.context and self.context.obj:
            return self.context.obj['USERNAME']
    
    def get_password( self ):
        if self.context and self.context.obj:
            return self.context.obj['PASSWORD']

    def add_action( self, action ):
        self.actions_log.append( action )

    def set_hosts( self, hosts ):
        print(hosts)
        self.hosts = hosts
    
    def get_hosts( self ):
        return self.hosts

    def set_stop_event( self, event ):
        self.stop_event = event
    
    def get_stop_event( self ) -> threading.Event:
        return self.stop_event

    def get_startup_time( self ):
        return self.startup_time

class Diamondback( Client ):
    def __init__( self, context=None, stop_event=None, mode='basic', skip_discovery=False, hosts=None, network=None ):
        super().__init__( context, stop_event=stop_event, hosts=hosts, network=network )
        self.logger = logging.getLogger( 'diamondback' )

        self.set_mode( mode )
        self.skip_discovery = skip_discovery

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

        self.logger.info( 'initialized diamondback training agent...' )

    def query_public_ip_info(self, ip_address: Optional[str] = None, 
                            timeout: int = 10,
                            use_backup: bool = True) -> Dict:
        """
        Query public IP address information from online services.
        
        Args:
            ip_address: Specific IP to query. If None, queries your own public IP.
            timeout: Request timeout in seconds.
            use_backup: If True, tries backup service if primary fails.
        
        Returns:
            Dictionary containing IP information.
        """
        
        # Primary service: ipapi.co (no API key required for basic usage)
        primary_url = f"https://ipapi.co/{ip_address or ''}/json/"
        
        # Backup service: ipinfo.io (allows limited requests without API key)
        backup_url = f"https://ipinfo.io/{ip_address or ''}/json"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            # Try primary service
            response = requests.get(primary_url, headers=headers, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            
            # Normalize data from ipapi.co
            result = {
                'ip': data.get('ip'),
                'hostname': data.get('hostname'),
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country_name'),
                'country_code': data.get('country_code'),
                'postal_code': data.get('postal'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'timezone': data.get('timezone'),
                'org': data.get('org'),
                'asn': data.get('asn'),
                'service': 'ipapi.co',
                'raw_response': data
            }
            
        except (requests.RequestException, json.JSONDecodeError) as e:
            if not use_backup:
                raise Exception(f"Failed to query IP information: {str(e)}")
            
            try:
                # Try backup service
                response = requests.get(backup_url, headers=headers, timeout=timeout)
                response.raise_for_status()
                data = response.json()
                
                # Normalize data from ipinfo.io
                loc = data.get('loc', ',').split(',')
                lat = float(loc[0]) if len(loc) > 0 and loc[0] else None
                lon = float(loc[1]) if len(loc) > 1 and loc[1] else None
                
                result = {
                    'ip': data.get('ip'),
                    'hostname': data.get('hostname'),
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country'),
                    'country_code': data.get('country'),
                    'postal_code': data.get('postal'),
                    'latitude': lat,
                    'longitude': lon,
                    'timezone': data.get('timezone'),
                    'org': data.get('org'),
                    'asn': None,  # ipinfo.io doesn't provide ASN in free tier
                    'service': 'ipinfo.io',
                    'raw_response': data
                }
                
            except Exception as backup_error:
                raise Exception(f"Both services failed. Primary: {str(e)}, Backup: {str(backup_error)}")
        
        return result

    def store_ip_info(self, ip_data: Dict) -> Location:
        """
        Store IP information in the database using an active SQLAlchemy session.
        
        Args:
            session: Active SQLAlchemy session
            ip_data: Dictionary containing IP information
        
        Returns:
            IPAddressInfo instance that was stored
        """
        ip_info = Location(
            ip=ip_data.get('ip'),
            hostname=ip_data.get('hostname'),
            city=ip_data.get('city'),
            region=ip_data.get('region'),
            country=ip_data.get('country'),
            country_code=ip_data.get('country_code'),
            postal_code=ip_data.get('postal_code'),
            latitude=ip_data.get('latitude'),
            longitude=ip_data.get('longitude'),
            timezone=ip_data.get('timezone'),
            org=ip_data.get('org'),
            asn=ip_data.get('asn'),
            raw_data=ip_data.get('raw_response')
        )
        
        self.session.add(ip_info)
        self.session.commit()
        
        return ip_info

    def set_network_services( self, services ):
        self.network_services = services

    def get_service_for( self, port, protocol='tcp' ):
        try:
            return self.network_services[f'{port}/{protocol}']
        except:
            return None
        
    def set_mode( self, mode ):
        self.mode = mode
    
    def get_mode( self ):
        return self.mode

    def set_commands( self, commands ):
        self.commands = commands

    def get_commands( self ):
        return self.commands

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
    
    def speak_text( self, text_to_read, configuration=None ):
        audio_chunks = []

        if text_to_read.find( '.' ) != -1:
            text_to_read = text_to_read.replace( '.', ' dot ' )

        for audio_chunk in self.speech_voice.synthesize(text_to_read):
            # AudioChunk has .audio_int16_array property that returns numpy array
            audio_chunks.append(audio_chunk.audio_int16_array)
        
        audio_data = np.concatenate(audio_chunks)
        sd.play(audio_data, samplerate=self.speech_voice.config.sample_rate)
        sd.wait()

    def lookup_ip_details( self, current_ip ):
        self.logger.info( f'lookup location details by IP address: {current_ip}' )
        return self.session.query( Location ).filter( Location.ip == current_ip ).first( )

    def run( self ):
        my_ip_info = self.query_public_ip_info()
        my_location = NotImplementedError
        try:
            my_location = self.lookup_ip_details( my_ip_info['ip'] )
        except:
            pass

        if not my_location:
            self.logger.info( 'no record of this location, store one now please' )
            self.ipaddress_details = self.store_ip_info( my_ip_info )
        else:
            self.logger.info( 'using previously stored record of this location' )
            self.ipaddress_details = my_location

        self.logger.info( 'starting agent, run initial discovery' )
        local_network = get_network_cidr_platform_specific()
        a = ARPScan(    self.action_results, 
                        location = my_location,
                        target_address=local_network, 
                        session=self.session ).run()

        self.logger.info( f'arp scan of {local_network} completed...' )
        hosts_found_via_arp = a.get_output()
        self.logger.info( f'found {len(hosts_found_via_arp)} hosts' )

        self.set_hosts( hosts_found_via_arp )

        if self.get_network():
            self.logger.info( f'user specified target subnet of {self.get_network()}, scan this for more potential targets' )
            a = ICMPScan(   self.action_results, 
                            target_address=self.get_network(), 
                            timeout=10,
                            location=self.ipaddress_details,
                            max_threads=50,
                            session=self.session ).run( )
            self.logger.info( f'ICMP scan of {self.get_network()} completed...' )
            hosts_found_via_icmp = a.get_output()
            self.logger.info( f'found {len(hosts_found_via_icmp)} hosts via ICMP' )

            self.get_hosts().extend( hosts_found_via_icmp )
            self.logger.info( f'extended possible targets by {len(hosts_found_via_icmp)} more' )

        while not self.get_stop_event( ).is_set( ):
            valid_targets     = []
            valid_ssh_targets = []
            try:
                self.logger.info( 'event loop execute, disregard previous output(s)' )

                new_configuration = read_properties( self.path_to_configuration )
                new_serial  = new_configuration.getint('general','serial')

                if new_serial > self.configuration_serial:
                    self.logger.info( "******** UPDATE CONFIGURATION! **********")
                    self.configuration = new_configuration

                if not self.skip_discovery:
                    self.logger.info( '(re)discover live hosts on LAN')
                    a = ARPScan(    self.action_results, 
                                    target_address=get_network_cidr_platform_specific(), 
                                    location=self.ipaddress_details,
                                    session=self.session ).run( )
                    self.logger.info( f'arp scan completed found {len(a.get_output())} hosts...' )
                else:
                    self.logger.info( 'skipping host discovery this iteration' )

                self.logger.info( 'check for SSH targets' )
                for h in self.get_hosts( ):
                    host_record = self.lookup_host_by_address( h )
                    if not host_record:
                        self.logger.info( 'no past record of this host, save a new one' )
                        host_record = self.save_target( h )
                    self.logger.info( f'checking {host_record.address} for SSH' )
                    a = SSHConnectionAttempt(   self.action_results, 
                                                target_address=h, 
                                                username=self.get_username(), 
                                                location=self.ipaddress_details,
                                                password=self.get_password(), 
                                                session=self.session  ).run( )
                    self.logger.info( 'SSH connection attempt complete' )

                self.session.commit( )
                valid_targets += valid_ssh_targets
                self.logger.info( f"\n✓ Found {len(valid_ssh_targets)} active hosts SSH access:" )

                if self.get_mode( ) == 'basic':
                    for host in valid_ssh_targets:
                        self.logger.info(f"  - {host}")
                        a = SSHCommandExecution( self.action_results, 
                                                target_address=host, 
                                                username=self.get_username(), 
                                                password=self.get_password(), 
                                                commands=self.get_commands(),
                                                session=self.session ).run( )
            except KeyboardInterrupt:
                self.logger.info( 'stop event sent, shutdown dawg' )
                self.get_stop_event().set( )
            except:
                self.logger.error( "FAILED execution!" )
                tb = traceback.format_exc( )
                self.logger.error( tb )
            Sleep(  self.action_results,
                    input=10,
                    location=my_location,
                    session=self.session ).run( )
