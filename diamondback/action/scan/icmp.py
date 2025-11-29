import ipaddress
import logging
import sys
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from scapy.all import *

from diamondback.action import call_before_decorator,Action

class ICMPScan( Action ):
    def __init__( self, *args, **kwargs ):
        """
        Initialize ICMP scanner
        
        Args:
            cidr: Network in CIDR notation (e.g., "192.168.1.0/24")
            timeout: Timeout for each ping in seconds
            max_threads: Maximum number of concurrent threads
        """
        super().__init__( *args, **kwargs )
        self.logger = logging.getLogger( 'arpscan' )

        try:
            i = self.get_input( )
            self.network = ipaddress.ip_network(i, strict=False)
        except:
            self.logger.warning( f"woah careful, this is not a valid network? {i}" )

        if "network" in kwargs and kwargs["network"]:
            if type(kwargs["network"]) == str:
                self.network = ipaddress.ip_network( kwargs["network"] )

        if 'timeout' in kwargs:
            self.timeout = kwargs['timeout']
        else:
            self.timeout = 5

        if 'max_threads' in kwargs:
            self.max_threads = kwargs['max_threads']
        else:
            self.max_threads = 50

        self.alive_hosts = []
        self.lock = threading.Lock()
        
    def ping_host(self, ip):
        """
        Send ICMP echo request to a single host
        
        Args:
            ip: IP address to ping
            
        Returns:
            tuple: (ip, True/False) indicating if host responded
        """
        try:
            self.logger.debug( f"ping {ip}" )
            # Create ICMP packet
            packet = IP(dst=str(ip))/ICMP()
            
            # Send packet and wait for reply
            reply = sr1(packet, timeout=self.timeout, verbose=0)
            if reply and reply.haslayer(ICMP):
                # Check if it's an echo reply (type 0)
                if reply[ICMP].type == 0:
                    return (str(ip), True)
                # Host exists but returned different ICMP type (e.g., destination unreachable)
                else:
                    return (str(ip), False)
            else:
                return (str(ip), False)
        except Exception as e:
            return (str(ip), False)
    
    @call_before_decorator
    def run( self ):
        """
        Scan entire network for alive hosts
        
        Returns:
            list: List of IP addresses that responded to ping
        """
        self.logger.info(f"[*] Starting ICMP scan on {self.network}")
        self.logger.info(f"[*] Total hosts to scan: {self.network.num_addresses}")
        self.logger.info(f"[*] Timeout: {self.timeout}s per host")
        self.logger.info(f"[*] Max threads: {self.max_threads}")
        
        start_time = datetime.utcnow()
        
        # Get all host IPs (excluding network and broadcast for IPv4)
        if self.network.version == 4:
            # For /32 and /31, include all addresses
            if self.network.prefixlen >= 31:
                hosts = list(self.network.hosts()) or [self.network.network_address]
            else:
                hosts = list(self.network.hosts())
        else:
            # IPv6
            hosts = list(self.network.hosts())
        
        if not hosts:
            hosts = [self.network.network_address]
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all ping tasks
            futures = {executor.submit(self.ping_host, ip): ip for ip in hosts}
            
            # Process results as they complete
            for future in as_completed(futures):
                ip, is_alive = future.result()
                if is_alive:
                    with self.lock:
                        self.alive_hosts.append(ip)
                    self.logger.info(f"[+] Host {ip} is alive")
        executor.shutdown(wait=True) # Blocks until all tasks are done
        elapsed_time = datetime.utcnow() - start_time
        
        # self.logger.info summary
        self.logger.info(f"[*] Scan completed in {elapsed_time}")
        self.logger.info(f"[*] Found {len(self.alive_hosts)} alive hosts out of {len(hosts)} scanned")
        self.set_output( self.alive_hosts )

        return self

