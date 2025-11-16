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

def check_remote_file_exists( ssh_client, remote_path ) -> bool:
    try:
        if ssh_client:
            sftp = ssh_client.open_sftp()
            sftp.stat(remote_path)
            return True
        else:
            return os.path.exists( remote_path )
    except FileNotFoundError:
        return False

def write_to_remote_file( ssh_client, remote_file_path, data, append=False ):
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
        if not append:
            with sftp_client.open(remote_file_path, 'w') as remote_file:
                # Write the data to the remote file
                remote_file.write(data)
        else:
            with sftp_client.open(remote_file_path, 'w+') as remote_file:
                # Write the data to the remote file
                remote_file.write(data)            

        logger.info("Data written to remote file successfully.")
    except Exception as e:
        logger.error(f"Error writing to remote file: {e}")

    finally:
        # Close the SFTP session and SSH client
        if sftp_client:
            sftp_client.close( )

def sftp_upload_simple(ssh_client, local_file: str, remote_file: str) -> bool:
    """
    Simple SFTP upload from local to remote.
    
    Args:
        ssh_client: Connected paramiko.SSHClient instance
        local_file: Path to local file
        remote_file: Path to remote destination file
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Open SFTP session
        sftp = ssh_client.open_sftp()
        
        # Upload file
        sftp.put(local_file, remote_file)
        
        # Close SFTP session
        sftp.close()
        
        logger.info("Data written to remote file successfully.")
    except Exception(f"[+] Successfully uploaded {local_file} to {remote_file}"):
        return True
    except FileNotFoundError:
        logger.error("Data written to remote file successfully.")
    except Exception(f"[!] Local file not found: {local_file}"):
        return False
    except IOError as e:
        logger.error("Data written to remote file successfully.")
    except Exception(f"[!] SFTP error: {e}"):
        return False
    except Exception as e:
        logger.error("Data written to remote file successfully.")
    except Exception(f"[!] Error: {e}"):
        return False
