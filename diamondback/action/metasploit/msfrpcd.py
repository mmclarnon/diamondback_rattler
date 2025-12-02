"""
Interface with Metasploit RPCd to control Metasploit from DiamondBack. Wildly
enough, you MUST setup SSL on the host where Metasploit is running for the daemon
to work at all!!

https://github.com/rapid7/metasploit-framework/issues/15569
"""
import json
import logging
import msgpack
import socket
import time
import traceback
from diamondback.action import call_before_decorator,Action
from diamondback.support import add_inbound_accept_rule,ufw_allow_port,ufw_remove_port
import requests
import json
import time
from typing import Dict, List, Optional, Any

class MSFJSONRPCConnection:
    """
    A Python client for interacting with Metasploit Framework via JSON-RPC API.
    
    This class provides methods to authenticate, list modules, and execute
    auxiliary or exploit modules through the Metasploit RPC service.
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 55553, 
                 ssl: bool = False, verify_ssl: bool = False):
        """
        Initialize the Metasploit RPC client.
        
        Args:
            host: The hostname or IP address of the Metasploit RPC server
            port: The port number for the RPC service (default: 55553)
            ssl: Whether to use SSL/TLS for the connection
            verify_ssl: Whether to verify SSL certificates
        """
        self.host       = host
        self.port       = port
        self.ssl        = ssl
        self.verify_ssl = verify_ssl
        self.token      = None
        self.headers    = {"Content-Type": "application/json"}
        
        self.logger     = logging.getLogger( self.__class__.__name__.lower() )

        # Build the base URL
        protocol = "https" if ssl else "http"
        #
        # this is taken from a running Kali instance. the path is specific
        self.base_url = f"{protocol}://{host}:{port}/api/v1/json-rpc"
        
        # Configure session for connection pooling
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if not verify_ssl:
            # Suppress SSL warnings if verification is disabled
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def _make_request( self, method: str, params: List = None ) -> Dict:
        """
        Make a JSON-RPC request to the Metasploit server.
        
        Args:
            method: The RPC method to call
            params: List of parameters for the method
            
        Returns:
            The response from the server as a dictionary
            
        Raises:
            ConnectionError: If unable to connect to the server
            ValueError: If the server returns an error
        """
        if params is None:
            params = []
            
        # Add auth token to params if available (except for auth.login)
        if self.token and method != "auth.login_noauth":
            params = [self.token] + params
        
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "id": 1,
            "params": params
        }
        
        try:
            response = self.session.post(
                self.base_url,
                data=json.dumps(payload),
                headers=self.headers,
                timeout=30
            )
            self.logger.info( response.content )
            response.raise_for_status()
            
            result = response.json()
            
            if "error" in result:
                raise ValueError(f"RPC Error: {result['error']}")
                
            return result.get("result", {})
            
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to connect to Metasploit RPC: {e}")
    
    def login(self, username: str, password: str) -> bool:
        """
        Authenticate with the Metasploit RPC server.
        
        Args:
            username: The username for authentication
            password: The password for authentication
            
        Returns:
            True if authentication successful, False otherwise
            
        Raises:
            ConnectionError: If unable to connect to the server
        """
        try:
            result = self._make_request("auth.login", [username, password])
            
            if result.get("result") == "success":
                self.token = result.get("token")
                self.logger.info(f"Successfully authenticated. Token: {self.token[:8]}...")
                return True
            else:
                self.logger.info(f"Authentication failed: {result}")
                return False
        except Exception as e:
            self.logger.error(f"Login failed: {e}")
            self.logger.error( traceback.format_exc() )
            return False
    
    def logout(self) -> bool:
        """
        Logout from the Metasploit RPC server.
        
        Returns:
            True if logout successful, False otherwise
        """
        if not self.token:
            self.logger.info("Not logged in")
            return False
            
        try:
            result = self._make_request("auth.logout", [self.token])
            if result.get("result") == "success":
                self.token = None
                self.logger.info("Successfully logged out")
                return True
            return False
        except Exception as e:
            self.logger.info(f"Logout failed: {e}")
            return False
    
    def list_modules(self, module_type: str = None) -> Dict[str, List[str]]:
        """
        List available Metasploit modules.
        
        Args:
            module_type: Type of modules to list ('exploits', 'auxiliary', 
                        'post', 'payloads', 'encoders', 'nops', or None for all)
                        
        Returns:
            Dictionary with module types as keys and lists of module names as values
            
        Raises:
            ValueError: If not authenticated
            ConnectionError: If unable to connect to the server
        """
        if not self.token:
            raise ValueError("Not authenticated. Please login first.")
        
        modules = {}
        
        if module_type:
            module_types = [module_type]
        else:
            module_types = ["exploits", "auxiliary", "post", "payloads", "encoders", "nops"]
        
        for mtype in module_types:
            try:
                result = self._make_request(f"module.{mtype}", [])
                if "modules" in result:
                    modules[mtype] = result["modules"]
                    self.logger.info(f"Found {len(result['modules'])} {mtype} modules")
            except Exception as e:
                self.logger.info(f"Failed to list {mtype}: {e}")
                modules[mtype] = []
        
        return modules
    
    def get_module_info(self, module_type: str, module_name: str) -> Dict:
        """
        Get detailed information about a specific module.
        
        Args:
            module_type: The type of module ('exploit' or 'auxiliary')
            module_name: The full name of the module
            
        Returns:
            Dictionary containing module information
        """
        if not self.token:
            raise ValueError("Not authenticated. Please login first.")
        
        try:
            result = self._make_request("module.info", [module_type, module_name])
            return result
        except Exception as e:
            self.logger.info(f"Failed to get module info: {e}")
            return {}
    
    def execute(self, module_type: str, module_name: str, 
                options: Dict[str, Any] = None, payload: str = None,
                payload_options: Dict[str, Any] = None) -> Dict:
        """
        Execute a Metasploit auxiliary or exploit module.
        
        Args:
            module_type: Type of module ('exploit' or 'auxiliary')
            module_name: Full name of the module to execute
            options: Dictionary of module options (RHOST, RPORT, etc.)
            payload: Payload to use (for exploit modules)
            payload_options: Dictionary of payload options
            
        Returns:
            Dictionary containing execution results
            
        Raises:
            ValueError: If not authenticated or invalid module type
            ConnectionError: If unable to connect to the server
        """
        if not self.token:
            raise ValueError("Not authenticated. Please login first.")
        
        if module_type not in ["exploit", "auxiliary"]:
            raise ValueError("Module type must be 'exploit' or 'auxiliary'")
        
        if options is None:
            options = {}
        if payload_options is None:
            payload_options = {}
        
        try:
            # Create a console to run the module
            console_result = self._make_request("console.create", [])
            console_id = console_result.get("id")
            
            if not console_id:
                raise ValueError("Failed to create console")
            
            self.logger.info(f"Created console with ID: {console_id}")
            
            # Build the command sequence
            commands = []
            
            # Use the module
            commands.append(f"use {module_type}/{module_name}")
            
            # Set options
            for key, value in options.items():
                commands.append(f"set {key} {value}")
            
            # Set payload if specified (for exploits)
            if module_type == "exploit" and payload:
                commands.append(f"set PAYLOAD {payload}")
                for key, value in payload_options.items():
                    commands.append(f"set {key} {value}")
            
            # Execute the module
            if module_type == "exploit":
                commands.append("exploit -j")  # Run as job
            else:
                commands.append("run -j")  # Run auxiliary as job
            
            # Execute commands
            results = []
            for cmd in commands:
                self.logger.info(f"Executing: {cmd}")
                result = self._make_request("console.write", [console_id, cmd + "\n"])
                time.sleep(0.5)  # Give console time to process
                
                # Read console output
                output = self._make_request("console.read", [console_id])
                if output.get("data"):
                    self.logger.info(output["data"])
                    results.append(output["data"])
            
            # Get job status
            jobs = self._make_request("job.list", [])
            
            # Clean up console
            self._make_request("console.destroy", [console_id])
            
            return {
                "success": True,
                "console_id": console_id,
                "output": "\n".join(results),
                "jobs": jobs
            }
            
        except Exception as e:
            self.logger.info(f"Execution failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def list_sessions(self) -> Dict:
        """
        List active sessions.
        
        Returns:
            Dictionary of active sessions
        """
        if not self.token:
            raise ValueError("Not authenticated. Please login first.")
        
        try:
            result = self._make_request("session.list", [])
            return result
        except Exception as e:
            self.logger.info(f"Failed to list sessions: {e}")
            return {}
    
    def list_jobs(self) -> Dict:
        """
        List active jobs.
        
        Returns:
            Dictionary of active jobs
        """
        if not self.token:
            raise ValueError("Not authenticated. Please login first.")
        
        try:
            result = self._make_request("job.list", [])
            return result
        except Exception as e:
            self.logger.info(f"Failed to list jobs: {e}")
            return {}

class MSFRPCClient:
    def __init__(self, host="127.0.0.1", port=55553, username="msf", password="msfpassword"):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.token = None
        self.sock = None

    def connect(self):
        """Establish a TCP connection to msfrpcd."""
        self.sock = socket.create_connection((self.host, self.port))

    def send(self, method, params=[]):
        """Send a MessagePack RPC request."""
        if not self.sock:
            raise RuntimeError("Not connected")
        req = [method] + params
        packed = msgpack.packb(req)
        self.sock.sendall(packed)

        # Receive response
        data = self.sock.recv(4096)
        return msgpack.unpackb(data, raw=False)

    def login(self):
        """Authenticate and store session token."""
        resp = self.send("auth.login", [self.username, self.password])
        if resp.get("result") == "success":
            self.token = resp["token"]
            print(f"Logged in successfully. Token: {self.token}")
        else:
            raise RuntimeError("Login failed")

    def call(self, method, params=[]):
        """Make an authenticated RPC call."""
        if not self.token:
            raise RuntimeError("Not authenticated")
        return self.send(method, [self.token] + params)

class MsfRPC( Action ):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.logger   = logging.getLogger( 'msfrpc' )

        self.command  = kwargs.get("command", 'exploit' )
        self.argument = kwargs.get("command_argument", "multi/handler" )
        self.client   = None
        self.payload  = kwargs.get( "payload" )

        self.lport    = kwargs.get("lport", 5555)
        self.container_name = kwargs.get("container", "metasploit")
        self.host = kwargs.get("host", '127.0.0.1' )
        self.port = kwargs.get("port", 55553)
        self.user = kwargs.get("user", "msf")
        self.password       = kwargs.get("password", "msfpassword")
        self.rpc_connection = None
        self.token          = None        

    def _send(self, method, params=None):
        """Send a request to msfrpcd and return the response"""
        if params is None:
            params = []
        req = {
            "method": method,
            "token": self.token,
            "id": 1,
            "params": params
        }
        packed = msgpack.packb(req)
        self.rpc_connection.sendall(packed)
        data = self.rpc_connection.recv(4096)
        return msgpack.unpackb(data, raw=False)

    def open( self ):
        """Connect to msfrpcd and authenticate"""
        self.logger.info( f"connecting via RPC to {self.host} on port {self.port} as {self.user} with password {self.password}" )
        # self.client = MSFRPCClient(host="127.0.0.1", port=55553, username="msf", password="msfpassword")
        # self.client.connect()
        # self.client.login()
        
        self.client = MSFJSONRPCConnection( host=self.host, 
                                            port=self.port )
        return self.client.login( self.user, self.password )

    def run( self ):
        """Setup a generic payload handler for Meterpreter on port 5555"""
        self.logger.info( "executing MSFRPC action" )
        is_open = self.open( )

        if is_open:
            modules = self.client.list_modules()
            self.logger.info( "Available metasploit modules:" )
            for m in modules:
                self.logger.info(m)
        else:
            self.logger.error("Login failed.")

        # Create a handler job
        lhost = "0.0.0.0"
        lport = 5555

        opts = {
            "Payload": self.payload,
            "LHOST": lhost,
            "LPORT": lport
        }

        #resp = self.client.call("module.execute", [self.command, self.argument, opts])
        #self.logger.info("Handler setup response:", resp)

# Example usage
if __name__ == "__main__":
    # Initialize the client
    msf = MetasploitRPC(host="127.0.0.1", port=55553, ssl=True)
    
    # Login to the RPC service
    # Note: You need to start msfrpcd first:
    # msfrpcd -P yourpassword -S -a 127.0.0.1
    if msf.login("msf", "yourpassword"):
        
        # List available modules
        modules = msf.list_modules("auxiliary")
        print(f"\nTotal auxiliary modules: {len(modules.get('auxiliary', []))}")
        
        # Example: Execute a simple auxiliary module (TCP port scanner)
        scan_result = msf.execute(
            module_type="auxiliary",
            module_name="scanner/portscan/tcp",
            options={
                "RHOSTS": "192.168.1.0/24",
                "PORTS": "22,80,443,445",
                "THREADS": 10
            }
        )
        
        print(f"\nScan result: {scan_result}")
        
        # List active sessions and jobs
        sessions = msf.list_sessions()
        print(f"\nActive sessions: {sessions}")
        
        jobs = msf.list_jobs()
        print(f"\nActive jobs: {jobs}")
        
        # Logout
        msf.logout()