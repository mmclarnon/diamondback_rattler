import logging
import os
import platform
import re
import subprocess

from urllib.parse import urlparse, unquote

from diamondback.action import call_before_decorator,Action
from diamondback.domain import *

class HTTPGet( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'httpget' )
        self.logger.info( 'initializing HTTP GET action' )

        i = self.get_input( )
        p = self.password
        u = self.username

        if 'url' in kwargs:
            self.url = kwargs['url']
            self.logger.info( f'downloading resource from {self.url} using HTTP' )
        else:
            raise RuntimeWarning('cannot actually retrieve anything, no URL was supplied!')
        
        if 'local_filename' in kwargs:
            self.local_filename = kwargs['local_filename']
            self.logger.info( f'saving URL to local file {self.local_filename}' )
        else:
            self.local_filename = None

        if 'local_file' in kwargs:
            self.local_filename = kwargs['local_file']
            self.logger.info( f'saving URL to local file {self.local_filename}' )
        else:
            self.local_filename = None

        self.logger.info( f'using supplied target of {i}, username of {u}, password of {p}' )
    
    def download_with_curl( self, url, local_filename=None ):
        """
        Download a file from a URL using curl via subprocess (safer version).
        
        Args:
            url: The URL to download from
            local_filename: The local filename to save the downloaded content
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.logger.info( 'downloading via CURL' )
            # If no local filename provided, extract it from the URL
            if local_filename is None:
                parsed_url = urlparse(url)
                # Get the path component and extract the filename
                path = unquote(parsed_url.path)  # Decode URL-encoded characters
                local_filename = os.path.basename(path)
                # If still no filename (e.g., URL ends with /), use a default
                if not local_filename:
                    local_filename = "download"
                    self.logger.info(f"Could not extract filename from URL, using '{local_filename}'")
                else:
                    self.logger.info(f"Using filename from URL: {local_filename}")

            # Build the command as a list (safer than shell=True)
            command = ["curl", "-L", "-o", local_filename, url]

            result = self.get_connection().execute( " ".join(command) )
        except FileNotFoundError:
            self.logger.info("Error: curl command not found. Please ensure curl is installed.")
            return False
        except Exception as e:
            self.logger.info(f"Unexpected error: {e}")
            return False

    def download_with_powershell(self, url, local_filename=None):
        """
        Download a file from a URL using PowerShell via subprocess.
        
        Args:
            url: The URL to download from
            local_filename: The local filename to save the downloaded content.
                          If None, uses the filename from the URL.
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # If no local filename provided, extract it from the URL
            if local_filename is None:
                parsed_url = urlparse(url)
                
                # Get the path component and extract the filename
                path = unquote(parsed_url.path)  # Decode URL-encoded characters
                local_filename = os.path.basename(path.rstrip('/'))
                
                # Handle query parameters that might contain the real filename
                if not local_filename or '.' not in local_filename:
                    if parsed_url.query:
                        # Look for common filename parameters
                        match = re.search(r'(?:file|filename|name|download)=([^&]+)', parsed_url.query)
                        if match:
                            potential_filename = unquote(match.group(1))
                            if '.' in potential_filename:
                                local_filename = os.path.basename(potential_filename)
                
                # If still no valid filename, use domain + default
                if not local_filename:
                    domain = parsed_url.netloc.replace('.', '_')
                    local_filename = f"{domain}_download"
                    self.logger.info(f"Could not extract filename from URL, using '{local_filename}'")
                else:
                    self.logger.info(f"Using filename from URL: {local_filename}")
            
            # Escape single quotes in the URL and filename for PowerShell
            url_escaped = url.replace("'", "''")
            filename_escaped = local_filename.replace("'", "''")
            
            # Build the PowerShell command with progress preference
            command = (
                f"$ProgressPreference = 'SilentlyContinue'; "
                f"Invoke-WebRequest -Uri '{url_escaped}' -OutFile '{filename_escaped}' -UseBasicParsing"
            )

            self.logger.info( command )

            result = self.get_connection().run_powershell( command )
            self.logger.info(f"Successfully downloaded {url} to {local_filename}")
            if result:
                self.logger.info( result )
            return True
        except FileNotFoundError:
            self.logger.info(f"Error: PowerShell not found. Please ensure {'PowerShell' if platform.system() == 'Windows' else 'PowerShell Core (pwsh)'} is installed.")
            return False
        except Exception as e:
            self.logger.info(f"Unexpected error: {e}")
            return False

    def download_with_certutil( self, url, local_filename=None ):
        """
        Download a file from a URL using certutil on Windows via subprocess.
        Note: certutil is a Windows-only utility primarily for certificates,
        but can be used to download files as a workaround.
        
        Args:
            url: The URL to download from
            local_filename: The local filename to save the downloaded content.
                          If None, uses the filename from the URL.
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # If no local filename provided, extract it from the URL
            if local_filename is None:
                parsed_url = urlparse(url)
                
                # Get the path component and extract the filename
                path = unquote(parsed_url.path)  # Decode URL-encoded characters
                local_filename = os.path.basename(path.rstrip('/'))
                
                # Handle query parameters that might contain the real filename
                if not local_filename or '.' not in local_filename:
                    if parsed_url.query:
                        # Look for common filename parameters
                        match = re.search(r'(?:file|filename|name|download)=([^&]+)', parsed_url.query)
                        if match:
                            potential_filename = unquote(match.group(1))
                            if '.' in potential_filename:
                                local_filename = os.path.basename(potential_filename)
                
                # If still no valid filename, use domain + default
                if not local_filename:
                    domain = parsed_url.netloc.replace('.', '_')
                    local_filename = f"{domain}_download"
                    self.logger.info(f"Could not extract filename from URL, using '{local_filename}'")
                else:
                    self.logger.info(f"Using filename from URL: {local_filename}")
            
            # If file already exists, delete it first (certutil can be picky)
            if os.path.exists(local_filename):
                try:
                    os.remove(local_filename)
                except:
                    pass  # Continue even if we can't delete
            
            # Build the certutil command
            # -urlcache: use URL cache
            # -split: allow downloading in parts (for larger files)
            # -f: force overwrite
            command = ["c:\\windows\\system32\\certutil.exe", "-urlcache", "-split", "-f", url, local_filename]
            c = " ".join(command)
            self.logger.info( c )
            result = self.get_connection().execute( c, sudo=True )
            self.logger.info( result )
        except FileNotFoundError:
            self.logger.info("Error: certutil not found. This utility should be available on Windows.")
            return False
        except Exception as e:
            self.logger.info(f"Unexpected error: {e}")
            return False

    @call_before_decorator
    def run( self ):
        self.logger.info( 'starting HTTP GET action' )

        if self.get_connection().get_connection_type() == "ssh":
            self.download_with_curl( self.url, self.local_filename )
        elif self.get_connection().get_connection_type() == "winrm":
            self.download_with_powershell( self.url, self.local_filename )
        elif self.get_connection().get_connection_type() == "smb":
            self.download_with_certutil( self.url, self.local_filename )
        
        self.logger.info( 'HTTPGet action attempt action completed....' )
        return self

