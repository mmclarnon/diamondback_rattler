import ipaddress

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