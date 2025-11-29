import logging

from scapy.all import *
from support import get_network_cidr_platform_specific
from diamondback.action import call_before_decorator,Action

class NBNSScan( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( *args, **kwargs )
        self.logger = logging.getLogger( 'nbnscan' )
        self.logger.info( 'initializing NBNSScan action' )

        local_network = get_network_cidr_platform_specific()
        self.set_input( local_network )

        self.logger.info( f'using supplied target of {local_network}' )

    def sniff_nbns(self, duration=10):
        """
        Sniff NBNS (NetBIOS Name Service) broadcast frames over UDP
        and collect IP addresses.

        Args:
            duration (int): Length of time in seconds to sniff for packets.

        Returns:
            list: A list of unique IP addresses discovered.
        """
        ip_addresses = set()

        def process_packet(packet):
            # Check if packet has UDP layer on port 137 and NBNS response
            if packet.haslayer(UDP) and packet[UDP].sport == 137 or packet[UDP].dport == 137:
                if packet.haslayer(NBNSQueryResponse):
                    ip_addresses.add(packet[IP].src)

        # Sniff packets for the given duration
        sniff(filter="udp port 137", prn=process_packet, timeout=duration, store=False)

        return list(ip_addresses)

        self.set_output( hosts )
    
    @call_before_decorator
    def run( self ):
        self.logger.info( 'executing NBNS Scan action to discover Windows assets on target LAN' )
        self.set_output( self.sniff_nbns() )
        self.logger.info( f'NBNS scan complete, found {len(self.get_output())} hosts' )

        return self
