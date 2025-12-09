import logging

from diamondback.domain import Command
from diamondback.action import call_before_decorator,Action
from diamondback.connection.ssh import SSHClientWrapped

class AddUser( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'adduser' )
        self.logger.info( 'initializing Add User action' )

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )
    
        if "sudo" in kwargs:
            self.sudo = kwargs["sudo"]
        else:
            self.sudo = False

        if 'username' in kwargs:
            self.username = kwargs['username']
        else:
            self.username = None

        if 'username_to_add' in kwargs:
            self.new_username = kwargs['username_to_add']

        if 'new_password' in kwargs:
            self.new_password = kwargs['new_password']

    def create_user(self, username=None, full_name="", password=None):
        """
        Create a new user on Ubuntu Linux with sudo and adm group membership.
        Requires root/sudo privileges to run.
        """
        try:
            if not username:
                username = self.new_username 
            
            if not password:
                password = self.new_password

            if self.get_connection().get_connection_type().lower() == "ssh":
                self.logger.info( 'setup user creation using SSH' )

                cmd = [
                    '/usr/sbin/useradd',
                    '-m',  # Create home directory
                    '-s', '/bin/bash',  # Set bash as default shell
                    '-G', 'sudo,adm',  # Add to sudo and adm groups
                    #'-c', full_name,  # Full name/comment
                    username
                ]
            elif self.get_connection().get_connection_type().lower() == "winrm":
                self.logger.info( 'setup user creation using winrm' )
                cmd = [
                    'New-LocalUser',
                    '-Name', 
                    username,
                    '-Password', 
                    f'(ConvertTo-SecureString "{password}" -AsPlainText -Force)'
                ]   
            elif self.get_connection().get_connection_type().lower() == "smb":
                self.logger.info( 'setup user creation using SMB' )

                cmd = [
                    'net',
                    'user', 
                    username,
                    password,
                    '/add'
                ]  
            self.logger.info( cmd )
            
            self.logger.info(f"Creating user '{username}'...")
            output = self.get_connection().execute(" ".join(cmd), sudo=True)
            self.logger.info(f"User '{username}' created successfully")
            self.logger.debug( output )
            
            # Set password if provided
            if password and self.get_connection().get_connection_type().lower() == "ssh":
                self.logger.info(f"Setting password for '{username}'...")
                # Use chpasswd to set the password
                passwd_cmd = f'echo "{username}:{password}" | chpasswd'
                self.get_connection().execute(passwd_cmd, sudo=True)
                self.logger.info("Password set successfully")
            
                # Verify the user was created and show user info
                self.logger.info("Verifying user creation...")
                id_output = self.get_connection().execute(f'id {username}', sudo=True)
                self.logger.info(f"User info: {id_output}")
                
                # Show the groups
                groups_output = self.get_connection().execute(f'groups {username}', sudo=True)
                self.logger.info(f"Groups: {groups_output}")
        
            return True
        except Exception as e:
            self.logger.error( f"Unexpected error: {e}" )
            return False

    @call_before_decorator
    def run( self ):
        self.logger.info(f"adding new user on host {self.get_input()}...")
        
        self.create_user( )

        self.logger.info("adduser completed on target")
        return self
    
class RemoveUser( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'removeuser' )
        self.logger.info( 'initializing Remove User action' )

        i = self.get_input( )
        self.logger.info( f'using supplied target of {i}' )
    
        if "sudo" in kwargs:
            self.sudo = kwargs["sudo"]
        else:
            self.sudo = False

        if 'username' in kwargs:
            self.username = kwargs['username']
        else:
            self.username = None

        if 'username_to_remove' in kwargs:
            self.new_username = kwargs['username_to_remove']

    def remove_user(self, username=None ):
        """
        Removes an existing user on Ubuntu Linux.
        """
        try:
            if not username:
                username = self.new_username 
            if self.get_connection().get_connection_type().lower() == "ssh":
                cmd = [
                    '/usr/sbin/userdel',
                    username
                ]
                self.logger.info( cmd )
            elif self.get_connection().get_connection_type().lower() == "winrm":
                cmd = [
                    'Remove-LocalUser',
                    '-Name',
                    username                    
                ]   
            elif self.get_connection().get_connection_type().lower() == "smb":
                cmd = [
                    'net',
                    'user', 
                    username, 
                    '/delete',
                ]              
            self.logger.info(f"Removing user '{username}'...")
            output = self.get_connection().execute(" ".join(cmd), sudo=True)
            self.logger.info(f"User '{username}' REMOVED successfully")
            self.logger.info( output )

            return True
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            return False

    @call_before_decorator
    def run( self ):
        self.logger.info(f"\Removing user from host {self.get_input()}...")
        
        self.remove_user( )

        self.logger.info("remove completed on target")
        return self