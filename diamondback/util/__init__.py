import ipaddress

from scapy.all import *

def validate_cidr(cidr_string):
    """
    Validate CIDR notation
    
    Args:
        cidr_string: String in CIDR notation
        
    Returns:
        bool: True if valid CIDR
    """
    try:
        ipaddress.ip_network(cidr_string, strict=False)
        return True
    except ValueError:
        return False


def get_netbios_name(ip_address):
    """
    Sends an NBNS query to a given IP address and attempts to extract
    the NetBIOS machine name from the response.
    """
    try:
        # Construct an NBNS query for the "Workstation Service" (0x00)
        # We query for a specific service to get a name record.
        # The QUESTION_NAME can be anything, but using a common service helps.
        # The QUESTION_TYPE 'NB' is for NetBIOS Name Query.
        pkt = IP(dst=ip_address)/UDP(sport=137, dport=137)/NBNSQueryRequest(
            QUESTION_NAME="*", QUESTION_TYPE='NB', SUFFIX=0x00
        )

        # Send the packet and wait for a response
        ans, unans = sr(pkt, timeout=5, verbose=0)

        if ans:
            for s, r in ans:
                if r.haslayer(NBNSQueryResponse):
                    # Iterate through the NameRecords in the response
                    for name_record in r[NBNSQueryResponse].NameRecords:
                        # The machine name is typically found in a record
                        # with a specific suffix (e.g., 0x20 for server service)
                        # or can be inferred from other records.
                        # For a general machine name, we look for the name itself.
                        if name_record.SUFFIX == 0x20:  # Server service
                            return name_record.NAME.strip()
                        elif name_record.SUFFIX == 0x00: # Workstation Service
                            return name_record.NAME.strip()
            return None # No name found in response
        else:
            return None # No response received
    except Exception as e:
        print(f"Error: {e}")
        return None