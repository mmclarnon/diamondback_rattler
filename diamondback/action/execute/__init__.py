import logging
import multiprocessing
import random
import time

# Alternative: Context manager version
from contextlib import contextmanager

import paramiko
from typing import Optional, Dict, Tuple

from diamondback.action import call_before_decorator,Action
from connection.ssh import SSHClientWrapped
from domain import Command

class SSHCommandExecution( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'sshcommandexec' )
        self.logger.info( f'initializing {self.get_name()} action' )

        if "sudo" in kwargs:
            self.sudo = kwargs["sudo"]
        else:
            self.sudo = False

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )
    
        if 'commands' in kwargs:
            self.commands = kwargs['commands']
        else:
            self.commands = [ 'whoami' ]

        self.set_connection_type( 'ssh' )

    def execute_commands_on_host(self, commands, port=22):
        """
        Execute commands on a remote host via SSH.
        
        Args:
            host: IP address of the host
            username: SSH username
            password: SSH password
            commands: List of commands to execute
            port: SSH port
        """
        self.logger.info(f"[Process {multiprocessing.current_process().pid}]")
        host = self.get_input()
        try:
            client = self.get_connection( )
            if client:
                self.logger.info(f"[{host}] Successfully connected")
            
            #commands = ['hostname', 'whoami', 'date', 'ps aux | head -5', 'echo "the hacker D1@m0ndB@ck was here" >> suspicious_file.txt']
            # Execute each command
            if type(commands) == str:
                commands = [commands]

            for command in commands:
                self.logger.info(f"[{host}] Executing: {command}")

                c = self.lookup_command( command, 'ssh' )
                if not c:
                    self.logger.info( 'saving new command details' )
                    new_command         = Command( )
                    new_command.service = 'ssh'
                    new_command.value   = command
                    command_tokens = command.split(" ")
                    if command_tokens[0] != 'sudo':
                        new_command.name = command_tokens[0]
                    else:
                        new_command.name = command_tokens[1]

                    self.session.add( new_command )
                    self.session.commit( )
                else:
                    self.logger.info( f'found historical command reference {c.id}' )

                self.logger.info( 'calling execute on target' )
                r = client.execute( command,sudo=self.sudo )
                
                if r['out']:
                    self.logger.info(f"[{host}] Output:{r['out'][:200]}")  # Limit output length
                if r['err']:
                    self.logger.error(f"[{host}] Error: {r['err']}")
                
                time.sleep(random.randint(1,3))  # Small delay between commands
            
            # Close connection
            client.close()
            self.logger.info(f"[{host}] Connection closed")
        except Exception as e:
            self.logger.error(f"[{host}] Error: {str(e)}")
        return 0
    
    @call_before_decorator
    def run( self ):
        commands = self.commands
        if type(commands) == str:
            if commands.find(",") != -1:
                commands = commands.split(",")
            else:
                commands = [ commands ]
        # Step 3: Execute commands on SSH-accessible hosts using multiprocessing
        if commands:
            self.logger.info(f"Executing commands on host {self.get_input()}...")
            self.logger.info(f"Commands to execute: {list(commands)}")
            
            self.execute_commands_on_host(commands, 22)
            
            self.logger.info("✓ Command execution completed on all hosts")

        return self

def detect_package_manager(ssh_client: paramiko.SSHClient) -> Optional[Dict[str, str]]:
    """
    Detect the package manager available on the remote system.
    
    Args:
        ssh_client: An active Paramiko SSH connection
    
    Returns:
        Dictionary with package manager info or None if not found
        Format: {
            'manager': 'apt'|'dnf'|'yum'|'zypper'|'apk',
            'install_cmd': 'apt install -y'|'dnf install -y'|etc,
            'update_cmd': 'apt update'|'dnf check-update'|etc,
            'search_cmd': 'apt search'|'dnf search'|etc,
            'remove_cmd': 'apt remove -y'|'dnf remove -y'|etc
        }
    """
    
    # Define package managers and their commands
    package_managers = [
        {
            'name': 'apt',
            'check_cmd': 'which apt',
            'install_cmd': 'apt install -y {}',
            'update_cmd': 'apt update',
            'upgrade_cmd': 'apt upgrade -y',
            'search_cmd': 'apt search',
            'remove_cmd': 'apt remove -y {}',
            'distro': 'Debian/Ubuntu'
        },
        {
            'name': 'dnf',
            'check_cmd': 'which dnf',
            'install_cmd': 'dnf install -y {}',
            'update_cmd': 'dnf check-update',
            'upgrade_cmd': 'dnf upgrade -y',
            'search_cmd': 'dnf search',
            'remove_cmd': 'dnf remove -y {}',
            'distro': 'Fedora/RHEL 8+'
        },
        {
            'name': 'yum',
            'check_cmd': 'which yum',
            'install_cmd': 'yum install -y {}',
            'update_cmd': 'yum check-update',
            'upgrade_cmd': 'yum update -y',
            'search_cmd': 'yum search',
            'remove_cmd': 'yum remove -y {}',
            'distro': 'CentOS/RHEL 7'
        },
        {
            'name': 'zypper',
            'check_cmd': 'which zypper',
            'install_cmd': 'zypper install -y',
            'update_cmd': 'zypper refresh',
            'upgrade_cmd': 'zypper update -y',
            'search_cmd': 'zypper search',
            'remove_cmd': 'zypper remove -y',
            'distro': 'openSUSE/SLES'
        },
        {
            'name': 'apk',
            'check_cmd': 'which apk',
            'install_cmd': 'apk add {}',
            'update_cmd': 'apk update',
            'upgrade_cmd': 'apk upgrade',
            'search_cmd': 'apk search',
            'remove_cmd': 'apk del {}',
            'distro': 'Alpine'
        }
    ]
    
    for pm in package_managers:
        try:
            # Check if the package manager exists
            stdin, stdout, stderr = ssh_client.exec_command(pm['check_cmd'])
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status == 0:
                # Package manager found
                result = stdout.read().decode('utf-8').strip()
                if result:  # Ensure we got a path back
                    print(f"Detected package manager: {pm['name']} ({pm['distro']})")
                    return {
                        'manager': pm['name'],
                        'install_cmd': pm['install_cmd'],
                        'update_cmd': pm['update_cmd'],
                        'upgrade_cmd': pm['upgrade_cmd'],
                        'search_cmd': pm['search_cmd'],
                        'remove_cmd': pm['remove_cmd'],
                        'distro': pm['distro']
                    }
        except Exception as e:
            print(f"Error checking for {pm['name']}: {e}")
            continue
    
    print("No supported package manager found")
    return None


class RemotePackageManager:
    """
    A more comprehensive class for managing packages on remote systems
    """
    
    def __init__(self, ssh_client: paramiko.SSHClient):
        """
        Initialize with an active SSH connection
        
        Args:
            ssh_client: Active Paramiko SSH connection
        """
        self.ssh = ssh_client
        self.package_info = self.detect_package_manager()
        
        if not self.package_info:
            raise RuntimeError("No supported package manager found on remote system")
    
    def detect_package_manager(self) -> Optional[Dict[str, str]]:
        """Detect and return package manager information"""
        return detect_package_manager(self.ssh)
    
    def execute_command(self, command: str, sudo: bool = True) -> Tuple[int, str, str]:
        """
        Execute a command on the remote system
        
        Args:
            command: Command to execute
            sudo: Whether to use sudo
        
        Returns:
            Tuple of (exit_status, stdout, stderr)
        """
        if sudo and not command.startswith('sudo'):
            command = f'sudo {command}'
        
        stdin, stdout, stderr = self.ssh.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        
        return (
            exit_status,
            stdout.read().decode('utf-8'),
            stderr.read().decode('utf-8')
        )
    
    def update_package_cache(self) -> bool:
        """Update the package manager cache"""
        print(f"Updating package cache using {self.package_info['manager']}...")
        exit_status, stdout, stderr = self.execute_command(self.package_info['update_cmd'])
        
        if exit_status == 0 or (exit_status == 100 and self.package_info['manager'] == 'dnf'):
            # dnf returns 100 when there are updates available
            print("Package cache updated successfully")
            return True
        else:
            print(f"Failed to update package cache: {stderr}")
            return False
    
    def install_package(self, package_name: str, update_first: bool = False) -> bool:
        """
        Install a package on the remote system
        
        Args:
            package_name: Name of the package to install
            update_first: Whether to update package cache first
        
        Returns:
            bool: True if successful, False otherwise
        """
        if update_first:
            self.update_package_cache()
        
        command = f"{self.package_info['install_cmd']} {package_name}"
        print(f"Installing package '{package_name}' with: {command}")
        
        exit_status, stdout, stderr = self.execute_command(command)
        
        if exit_status == 0:
            print(f"Successfully installed {package_name}")
            return True
        else:
            print(f"Failed to install {package_name}: {stderr}")
            return False
    
    def install_multiple_packages(self, packages: list, update_first: bool = True) -> Dict[str, bool]:
        """
        Install multiple packages
        
        Args:
            packages: List of package names
            update_first: Whether to update package cache first
        
        Returns:
            Dictionary mapping package names to installation success
        """
        results = {}
        
        if update_first:
            self.update_package_cache()
            update_first = False  # Don't update again for each package
        
        for package in packages:
            results[package] = self.install_package(package, update_first=False)
        
        return results
    
    def remove_package(self, package_name: str) -> bool:
        """Remove a package from the remote system"""
        command = f"{self.package_info['remove_cmd']} {package_name}"
        print(f"Removing package '{package_name}' with: {command}")
        
        exit_status, stdout, stderr = self.execute_command(command)
        
        if exit_status == 0:
            print(f"Successfully removed {package_name}")
            return True
        else:
            print(f"Failed to remove {package_name}: {stderr}")
            return False
    
    def is_package_installed(self, package_name: str) -> bool:
        """Check if a package is installed"""
        if self.package_info['manager'] in ['apt']:
            command = f"dpkg -l | grep -E '^ii\\s+{package_name}'"
        elif self.package_info['manager'] in ['dnf', 'yum']:
            command = f"rpm -qa | grep -E '^{package_name}-[0-9]'"
        elif self.package_info['manager'] == 'zypper':
            command = f"zypper search -i {package_name}"
        elif self.package_info['manager'] == 'apk':
            command = f"apk info -e {package_name}"
        else:
            return False
        
        exit_status, stdout, stderr = self.execute_command(command, sudo=False)
        return exit_status == 0 and stdout.strip() != ""


# Example usage
def main():
    """Example of how to use the RemotePackageManager class"""
    
    # Create SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Connect to remote host
        ssh.connect(
            hostname='192.168.1.100',
            port=22,
            username='admin',
            password='password',  # Use key_filename='path/to/key' for key auth
            timeout=10
        )
        
        # Method 1: Using the standalone function
        pm_info = detect_package_manager(ssh)
        if pm_info:
            print(f"\nPackage Manager: {pm_info['manager']}")
            print(f"Install Command: {pm_info['install_cmd']}")
            
            # Install a package using the detected command
            install_cmd = f"sudo {pm_info['install_cmd']} htop"
            stdin, stdout, stderr = ssh.exec_command(install_cmd)
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status == 0:
                print("Package installed successfully")
        
        # Method 2: Using the RemotePackageManager class
        print("\n" + "="*50)
        print("Using RemotePackageManager class:")
        print("="*50)
        
        rpm = RemotePackageManager(ssh)
        
        # Check if package is installed
        if rpm.is_package_installed('curl'):
            print("curl is already installed")
        else:
            print("curl is not installed, installing...")
            rpm.install_package('curl', update_first=True)
        
        # Install multiple packages
        packages_to_install = ['wget', 'nano', 'git']
        results = rpm.install_multiple_packages(packages_to_install)
        
        print("\nInstallation Results:")
        for package, success in results.items():
            status = "✓" if success else "✗"
            print(f"  {status} {package}")
        
    except paramiko.AuthenticationException:
        print("Authentication failed")
    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        ssh.close()



@contextmanager
def remote_package_manager(hostname: str, username: str, password: str = None, 
                          key_filename: str = None, port: int = 22):
    """
    Context manager for RemotePackageManager
    
    Usage:
        with remote_package_manager('192.168.1.100', 'admin', password='pass') as rpm:
            rpm.install_package('htop')
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            key_filename=key_filename,
            timeout=10
        )
        
        rpm = RemotePackageManager(ssh)
        yield rpm
        
    finally:
        ssh.close()

# Usage with context manager
def example_with_context_manager():
    """Example using the context manager"""
    
    with remote_package_manager('192.168.1.100', 'admin', password='password') as rpm:
        # The connection is automatically handled
        print(f"Connected to system using {rpm.package_info['manager']}")
        
        # Install packages
        rpm.install_package('tmux', update_first=True)
        
        # Check installation
        if rpm.is_package_installed('tmux'):
            print("tmux installation verified")
