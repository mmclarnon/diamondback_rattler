"""
Methods to determine the CIDR address for the current network connection.
Handles cases where the host is not connected to any network.
"""
import configparser
import socket
import subprocess
import logging
import platform
import ipaddress
import os
import re
from typing import Optional, List, Tuple

import iptc

CURRENT_DIRECTORY = os.path.abspath( os.path.dirname(__file__) )
PARENT_DIRECTORY = os.path.abspath( os.path.dirname(CURRENT_DIRECTORY) )
DEFAULT_CONFIGURATION_FILE = 'configuration.ini'

logger = logging.getLogger( 'support' )

def delete_all_files(dir):
    """
    Delete all files in the specified directory.
    
    Parameters:
        dir (str): Path to the directory whose files should be deleted.
    """
    if not os.path.isdir(dir):
        raise ValueError(f"{dir} is not a valid directory")

    for filename in os.listdir(dir):
        file_path = os.path.join(dir, filename)
        if os.path.isfile(file_path):
            try:
                os.remove(file_path)
                logger.info(f"Deleted file: {file_path}")
            except Exception as e:
                logger.warning(f"Error deleting {file_path}: {e}")

def ufw_allow_port(port: int, protocol: str = "tcp"):
    """
    Allow inbound connections on a specific port using UFW.
    Default protocol is TCP.
    """
    try:
        cmd = ["sudo", "ufw", "allow", f"{port}/{protocol}"]
        print(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print(f"Port {port}/{protocol} allowed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error allowing port {port}/{protocol}: {e}")

def ufw_remove_port(port: int, protocol: str = "tcp"):
    """
    Remove inbound rule for a specific port if it exists using UFW.
    Default protocol is TCP.
    """
    try:
        cmd = ["sudo", "ufw", "delete", "allow", f"{port}/{protocol}"]
        print(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print(f"Port {port}/{protocol} rule removed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error removing port {port}/{protocol}: {e}")

def add_inbound_accept_rule(port, protocol="tcp", interface=None, source_ip=None):
    """
    Adds an inbound ACCEPT rule to the INPUT chain.

    Args:
        port (int): The destination port for the rule.
        protocol (str): The protocol (e.g., "tcp", "udp"). Defaults to "tcp".
        interface (str, optional): The inbound interface (e.g., "eth0").
        source_ip (str, optional): The source IP address or network (e.g., "192.168.1.0/24").
    """
    logger.info( f"update firewall to allow {protocol} port {port}" )
    table = iptc.Table(iptc.Table.FILTER)
    chain = iptc.Chain(table, "INPUT")

    rule = iptc.Rule()
    rule.protocol = protocol

    # Add interface if specified
    if interface:
        rule.in_interface = interface

    # Add source IP if specified
    if source_ip:
        rule.src = source_ip

    # Create a match for the destination port
    match = rule.create_match(protocol)
    match.dport = str(port)

    # Set the target to ACCEPT
    target = iptc.Target(rule, "ACCEPT")
    rule.target = target

    # Insert the rule into the chain
    chain.insert_rule(rule)
    logger.info(f"Inbound ACCEPT rule added for port {port}/{protocol}")

def update_iptables_rule_with_library(old_rule_params, new_rule_params):
    """
    Updates an iptables rule using the python-iptables library.
    old_rule_params: Dictionary containing parameters to identify the old rule.
                     Example: {"protocol": "tcp", "dport": "80", "target": "ACCEPT"}
    new_rule_params: Dictionary containing parameters for the new rule.
                     Example: {"protocol": "tcp", "dport": "8080", "target": "ACCEPT"}
    """
    try:
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, "INPUT")

        # Find and delete the old rule
        old_rule = iptc.Rule(chain)
        if "protocol" in old_rule_params:
            old_rule.protocol = old_rule_params["protocol"]
        if "dport" in old_rule_params:
            match = iptc.Match(old_rule, "tcp")
            match.dport = old_rule_params["dport"]
            old_rule.add_match(match)
        if "target" in old_rule_params:
            target = iptc.Target(old_rule, old_rule_params["target"])
            old_rule.target = target

        # Iterate and remove matching rules
        for rule in chain.rules:
            if rule.protocol == old_rule.protocol and \
               hasattr(rule, 'matches') and \
               any(m.dport == match.dport for m in rule.matches if m.name == 'tcp') and \
               rule.target.name == old_rule.target.name:
                chain.delete_rule(rule)
                logger.info(f"Old rule deleted: {old_rule_params}")
                break

        # Add the new rule
        new_rule = iptc.Rule(chain)
        if "protocol" in new_rule_params:
            new_rule.protocol = new_rule_params["protocol"]
        if "dport" in new_rule_params:
            match = iptc.Match(new_rule, "tcp")
            match.dport = new_rule_params["dport"]
            new_rule.add_match(match)
        if "target" in new_rule_params:
            target = iptc.Target(new_rule, new_rule_params["target"])
            new_rule.target = target

        chain.insert_rule(new_rule)
        logger.info(f"New rule added: {new_rule_params}")

    except Exception as e:
        logger.info(f"Error updating iptables rule with python-iptables: {e}")

def read_properties( path ) -> configparser.ConfigParser:
    our_configuration = None
    full_path_to_project_config = path
    logger.info( "reading properties, full path to configuration file is {}".format(path) )

    if os.path.exists(full_path_to_project_config):
        our_configuration = configparser.ConfigParser()        
        our_configuration.read( full_path_to_project_config )
        logger.debug( "all read" )
    return our_configuration

def get_network_cidr_stdlib() -> Optional[str]:
    """
    Determine the CIDR address of the current network using standard library only.
    Returns None if not connected to any network.
    
    Returns:
        str: CIDR notation of the network (e.g., "192.168.1.0/24") or None
    """
    try:
        # Get hostname and try to resolve it to an IP
        hostname = socket.gethostname()
        
        # Get all IP addresses associated with the hostname
        addr_info = socket.getaddrinfo(hostname, None)
        
        # Filter for IPv4 addresses that are not loopback
        ipv4_addresses = []
        for info in addr_info:
            if info[0] == socket.AF_INET:  # IPv4
                ip = info[4][0]
                if not ip.startswith('127.'):  # Not loopback
                    ipv4_addresses.append(ip)
        
        if not ipv4_addresses:
            return None
        
        # Use the first non-loopback IPv4 address
        ip_address = ipv4_addresses[0]
        
        # Try to determine subnet mask based on IP class (simplified approach)
        # This is a fallback method and may not be accurate for all networks
        ip_obj = ipaddress.IPv4Address(ip_address)
        
        # Make educated guess about subnet based on private IP ranges
        if ip_obj.is_private:
            first_octet = int(ip_address.split('.')[0])
            second_octet = int(ip_address.split('.')[1])
            
            if first_octet == 10:
                # Class A private: typically /8, but often subdivided to /24
                subnet_mask = '255.255.255.0'  # Assume /24 for practicality
            elif first_octet == 172 and 16 <= second_octet <= 31:
                # Class B private: typically /16, but often /24
                subnet_mask = '255.255.255.0'  # Assume /24 for practicality
            elif first_octet == 192 and second_octet == 168:
                # Class C private: typically /24
                subnet_mask = '255.255.255.0'
            else:
                subnet_mask = '255.255.255.0'  # Default assumption
        else:
            # For public IPs, default to /24 (this is just a guess)
            subnet_mask = '255.255.255.0'
        
        # Calculate network address
        ip_interface = ipaddress.IPv4Interface(f"{ip_address}/{subnet_mask}")
        network = ip_interface.network
        
        return str(network)
        
    except Exception as e:
        logger.info(f"Error determining network CIDR: {e}")
        return None


def get_network_cidr_platform_specific() -> Optional[str]:
    """
    Determine the CIDR address using platform-specific commands.
    More accurate than the standard library approach.
    
    Returns:
        str: CIDR notation of the network (e.g., "192.168.1.0/24") or None
    """
    system = platform.system().lower()
    
    try:
        if system == 'linux':
            return _get_cidr_linux()
        elif system == 'darwin':  # macOS
            return _get_cidr_macos()
        elif system == 'windows':
            return _get_cidr_windows()
        else:
            logger.info(f"Unsupported platform: {system}")
            return get_network_cidr_stdlib()  # Fallback to stdlib method
            
    except Exception as e:
        logger.info(f"Error with platform-specific method: {e}")
        return get_network_cidr_stdlib()  # Fallback to stdlib method


def _get_cidr_linux() -> Optional[str]:
    """Get CIDR on Linux using ip command."""
    try:
        # Try using 'ip' command (more modern)
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0 and result.stdout:
            # Extract default interface
            match = re.search(r'dev\s+(\S+)', result.stdout)
            if match:
                interface = match.group(1)
                
                # Get IP address and subnet for this interface
                addr_result = subprocess.run(['ip', 'addr', 'show', interface],
                                           capture_output=True, text=True, timeout=5)
                
                # Look for inet line (IPv4)
                inet_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', addr_result.stdout)
                if inet_match:
                    ip_with_prefix = inet_match.group(1)
                    network = ipaddress.IPv4Interface(ip_with_prefix).network
                    return str(network)
        
        # Fallback to ifconfig if ip command fails
        result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            # Parse ifconfig output
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if 'inet ' in line and '127.0.0.1' not in line:
                    # Extract IP and netmask
                    ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                    mask_match = re.search(r'netmask\s+(\S+)', line)
                    
                    if ip_match and mask_match:
                        ip_addr = ip_match.group(1)
                        netmask = mask_match.group(1)
                        
                        # Convert hex netmask if necessary
                        if netmask.startswith('0x'):
                            netmask_int = int(netmask, 16)
                            netmask = socket.inet_ntoa(netmask_int.to_bytes(4, 'big'))
                        
                        ip_interface = ipaddress.IPv4Interface(f"{ip_addr}/{netmask}")
                        return str(ip_interface.network)
        
        return None
        
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _get_cidr_macos() -> Optional[str]:
    """Get CIDR on macOS using ifconfig."""
    try:
        # Get default interface
        route_result = subprocess.run(['route', 'get', 'default'],
                                     capture_output=True, text=True, timeout=5)
        
        interface = None
        if route_result.returncode == 0:
            match = re.search(r'interface:\s+(\S+)', route_result.stdout)
            if match:
                interface = match.group(1)
        
        # Get network info from ifconfig
        result = subprocess.run(['ifconfig', interface] if interface else ['ifconfig'],
                              capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'inet ' in line and '127.0.0.1' not in line:
                    # Extract IP and netmask
                    match = re.match(r'\s*inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)', line)
                    if match:
                        ip_addr = match.group(1)
                        netmask_hex = match.group(2)
                        
                        # Convert hex netmask to decimal
                        if netmask_hex.startswith('0x'):
                            netmask_int = int(netmask_hex, 16)
                            netmask = socket.inet_ntoa(netmask_int.to_bytes(4, 'big'))
                        else:
                            netmask = netmask_hex
                        
                        ip_interface = ipaddress.IPv4Interface(f"{ip_addr}/{netmask}")
                        return str(ip_interface.network)
        
        return None
        
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _get_cidr_windows() -> Optional[str]:
    """Get CIDR on Windows using ipconfig."""
    try:
        result = subprocess.run(['ipconfig', '/all'], 
                              capture_output=True, text=True, timeout=5, shell=True)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            ip_addr = None
            subnet_mask = None
            
            for line in lines:
                # Look for IPv4 Address line
                if 'IPv4 Address' in line or 'IP Address' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        potential_ip = match.group(1)
                        if not potential_ip.startswith('127.'):
                            ip_addr = potential_ip
                
                # Look for Subnet Mask line
                if 'Subnet Mask' in line and ip_addr:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        subnet_mask = match.group(1)
                        break
            
            if ip_addr and subnet_mask:
                ip_interface = ipaddress.IPv4Interface(f"{ip_addr}/{subnet_mask}")
                return str(ip_interface.network)
        
        return None
        
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def get_network_cidr_netifaces() -> Optional[str]:
    """
    Determine the CIDR address using the netifaces library (requires installation).
    This is the most reliable cross-platform method.
    
    Install with: pip install netifaces
    
    Returns:
        str: CIDR notation of the network (e.g., "192.168.1.0/24") or None
    """
    try:
        import netifaces
    except ImportError:
        logger.info("netifaces library not installed. Install with: pip install netifaces")
        return get_network_cidr_platform_specific()  # Fallback
    
    try:
        # Get default gateway
        gateways = netifaces.gateways()
        if 'default' not in gateways or netifaces.AF_INET not in gateways['default']:
            return None
        
        # Get the default interface
        default_interface = gateways['default'][netifaces.AF_INET][1]
        
        # Get addresses for the default interface
        if default_interface not in netifaces.interfaces():
            return None
        
        addrs = netifaces.ifaddresses(default_interface)
        
        # Get IPv4 address info
        if netifaces.AF_INET not in addrs:
            return None
        
        ipv4_info = addrs[netifaces.AF_INET][0]
        ip_addr = ipv4_info.get('addr')
        netmask = ipv4_info.get('netmask')
        
        if not ip_addr or not netmask:
            return None
        
        # Calculate network CIDR
        ip_interface = ipaddress.IPv4Interface(f"{ip_addr}/{netmask}")
        network = ip_interface.network
        
        return str(network)
        
    except Exception as e:
        logger.info(f"Error using netifaces: {e}")
        return None


def get_all_network_cidrs() -> List[Tuple[str, str]]:
    """
    Get CIDR addresses for all active network interfaces.
    
    Returns:
        List of tuples: (interface_name, cidr_address)
    """
    networks = []
    
    try:
        import netifaces
        
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            
            if netifaces.AF_INET in addrs:
                for addr_info in addrs[netifaces.AF_INET]:
                    ip_addr = addr_info.get('addr')
                    netmask = addr_info.get('netmask')
                    
                    if ip_addr and netmask and not ip_addr.startswith('127.'):
                        try:
                            ip_interface = ipaddress.IPv4Interface(f"{ip_addr}/{netmask}")
                            network = ip_interface.network
                            networks.append((interface, str(network)))
                        except:
                            pass
                            
    except ImportError:
        logger.info("netifaces not available for listing all interfaces")
        
        # Fallback: try to get at least the default network
        default_cidr = get_network_cidr_platform_specific()
        if default_cidr:
            networks.append(("default", default_cidr))
    
    return networks


def parse_increment_regex(parameter: str = "increment", text: str = None) -> Optional[int]:
    """
    Parse parameter value using regex.
    Handles optional whitespace around the number.
    
    Args:
        text: String containing {parameter: number}
        parameter: Name of the parameter to search for (default: "increment")
    
    Returns:
        Integer value or None if not found
    
    Examples:
        parse_increment_regex("text {increment: 42}", "increment")  # Returns 42
        parse_increment_regex("text {count: 99}", "count")          # Returns 99
        parse_increment_regex("text {value: -5}", "value")          # Returns -5
    """
    # Escape parameter name to handle special regex characters
    escaped_param = re.escape(parameter)
    pattern = rf'\{{{escaped_param}:\s*(-?\d+)\s*\}}'
    match = re.search(pattern, text)
    
    if match:
        return int(match.group(1))
    return None

def parse_string_parameter(text: str, parameter: str = "replace") -> Optional[str]:
    """
    Parse string parameter value using regex.
    Handles optional whitespace around the string.
    
    Args:
        text: String containing {parameter: string_value}
        parameter: Name of the parameter to search for (default: "replace")
    
    Returns:
        String value or None if not found
    
    Examples:
        parse_string_parameter("text {replace: hello}", "replace")  # Returns "hello"
        parse_string_parameter("text {name: John}", "name")         # Returns "John"
        parse_string_parameter("text {file: /tmp/test.txt}", "file") # Returns "/tmp/test.txt"
    """
    # Escape parameter name to handle special regex characters
    escaped_param = re.escape(parameter)
    # Match anything except closing brace, then strip whitespace
    pattern = rf'\{{{escaped_param}:\s*([^}}]+?)\s*\}}'
    match = re.search(pattern, text)
    
    if match:
        return match.group(1).strip()
    return None            

def main():
    """Test the different methods."""
    logger.info("Network CIDR Detection Test")
    logger.info("=" * 50)
    
    # Test standard library method
    logger.info("\n1. Standard Library Method:")
    cidr = get_network_cidr_stdlib()
    if cidr:
        logger.info(f"   Network CIDR: {cidr}")
    else:
        logger.info("   No network connection detected")
    
    # Test platform-specific method
    logger.info("\n2. Platform-Specific Method:")
    cidr = get_network_cidr_platform_specific()
    if cidr:
        logger.info(f"   Network CIDR: {cidr}")
    else:
        logger.info("   No network connection detected")
    
    # Test netifaces method
    logger.info("\n3. Netifaces Method (most accurate):")
    cidr = get_network_cidr_netifaces()
    if cidr:
        logger.info(f"   Network CIDR: {cidr}")
    else:
        logger.info("   No network connection detected")
    
    # List all networks
    logger.info("\n4. All Network Interfaces:")
    networks = get_all_network_cidrs()
    if networks:
        for interface, cidr in networks:
            logger.info(f"   {interface}: {cidr}")
    else:
        logger.info("   No active network interfaces found")
