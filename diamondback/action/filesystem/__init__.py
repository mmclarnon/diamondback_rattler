import logging
import os

from diamondback.connection.ssh import SSHClientWrapped

logger = logging.getLogger('filesystem')

def check_file_exists( ssh_client, remote_path ) -> bool:
    try:
        if ssh_client:
            sftp = ssh_client.open_sftp()
            sftp.stat(remote_path)
            return True
        else:
            return os.path.exists( remote_path )
    except FileNotFoundError:
        return False

def execute_command_via_ssh( ssh_client, command, sudo=False ):
    if not sudo:
        stdin, stdout, stderr = ssh_client.exec_command( command )
    else:
        wrapped_client = SSHClientWrapped( client=ssh_client )
        wrapped_client.execute( command, sudo )
        
    logger.debug( stderr.readlines() )
    return( stdout.readlines() )

def write_to_remote_file( ssh_client, remote_file_path, data ):
    """Writes data to a file on a remote server using Paramiko."""
    sftp_client = None
    try:
        logger.info( 'attempting to write to {}'.format(remote_file_path) )
        directory = os.path.dirname( remote_file_path )
        logger.info( directory )
        execute_command_via_ssh( ssh_client, "mkdir -p {}".format(directory) )
        
        # Open an SFTP session
        sftp_client = ssh_client.open_sftp()

        # Open the remote file in write mode
        with sftp_client.open(remote_file_path, 'w') as remote_file:
            # Write the data to the remote file
            remote_file.write(data)

        logger.info("Data written to remote file successfully.")
    except Exception as e:
        logger.error(f"Error writing to remote file: {e}")

    finally:
        # Close the SFTP session and SSH client
        if sftp_client:
            sftp_client.close( )