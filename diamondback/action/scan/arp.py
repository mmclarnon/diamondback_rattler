import logging

from scapy.all import *

from diamondback.action import *

class ARPScan( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( *args, **kwargs )
        self.logger = logging.getLogger( 'arpscan' )
        self.logger.info( 'initializing ARPScan action' )

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )

    def discover_hosts_on_subnet( self, network_range=None, timeout=10 ):
        """
        Discover active hosts on the local subnet using ARP scan.
        
        Args:
            network_range: CIDR notation of the network to scan
            timeout: Timeout for ARP responses
        
        Returns:
            List of IP addresses of discovered hosts
        """
        if not network_range:
            network_range = self.get_input( )

        self.logger.info(f"Scanning network: {network_range}")
        
        # Create ARP packet
        arp    = ARP(pdst=network_range)
        ether  = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        # Send packet and receive responses
        result = srp(packet, timeout=timeout, verbose=True)[0]
        
        # Extract IP addresses from responses
        hosts = []
        for sent, received in result:
            hosts.append(received.psrc)

        self.set_output( hosts )
        self.logger.info( self.get_output() )
    
    @call_before_decorator
    def run( self ):
        self.logger.info( 'executing ARP Scan action to discover assets on target LAN' )
        self.discover_hosts_on_subnet( )
        self.logger.info( f'arp scan complete, found {len(self.get_output())} hosts' )

        return self
