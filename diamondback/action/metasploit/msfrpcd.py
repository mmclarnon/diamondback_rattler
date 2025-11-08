import logging
import msgpack
import socket
import subprocess
import threading
import time
from diamondback.action import call_before_decorator,Action
from diamondback.support import add_inbound_accept_rule,ufw_allow_port,ufw_remove_port

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

class MsfRPC(Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.logger = logging.getLogger( 'msfrpc' )

        self.command = kwargs.get("command", 'exploit' )
        self.argument = kwargs.get("command_argument", "multi/handler" )

        self.payload = kwargs.get( "payload" )

        self.lport = kwargs.get("lport", 5555)
        self.container_name = kwargs.get("container", "metasploit")
        self.host = kwargs.get("host", '127.0.0.1' )
        self.port = kwargs.get("port", 55553)
        self.user = kwargs.get("user", "msf")
        self.password = kwargs.get("password", "msfpassword")
        self.rpc_connection = None
        self.token = None        

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

    def open(self):
        """Connect to msfrpcd and authenticate"""
        time.sleep( 20 )
        self.logger.info( f"connecting via RPC to {self.host} on port {self.port}" )
        self.client = MSFRPCClient(host="127.0.0.1", port=55553, username="msf", password="msfpassword")
        self.client.connect()
        self.client.login()

    def launch_msfrpcd(self):
        """
        Launch the Metasploit msfrpcd daemon inside the running container.
        """
        # docker run -it --rm -p 8443:55553   -e MSF_RPC_USER=msfuser   -e MSF_RPC_PASS=msfpassword   metasploitframework/metasploit-framework:latest   ./msfrpcd -U msfuser -P msfpassword -a 0.0.0.0 -f
        
        cmd = [
            "docker", "run", "-it", self.container_name,
            "/usr/src/metasploit-framework/msfrpcd",
            "-U", self.user,
            "-P", self.password,
            "-S",
            "-a", "0.0.0.0",
            "-p", str(self.port),
            "-f"   # foreground mode so the process stays attached
        ]

        try:
            # self.logger.info(f"Launching msfrpcd: {' '.join(cmd)}")
            # # Use Popen so the daemon stays running and you can interact with it
            # self.process = subprocess.Popen(cmd,
            #                         stdout=subprocess.PIPE,
            #                         stderr=subprocess.PIPE)
            # self.logger.info("msfrpcd daemon started successfully")
            return self.process
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error starting msfrpcd: {e}")
            return None

    def run( self ):
        #proc = self.launch_msfrpcd( )

        ufw_allow_port( self.port )

        """Setup a generic payload handler for Meterpreter on port 5555"""
        self.open( )

        if not self.rpc_connection:
            raise RuntimeError("Not connected. Call open() first.")

        # Create a handler job
        lhost = "0.0.0.0"
        lport = 5555

        opts = {
            "Payload": self.payload,
            "LHOST": lhost,
            "LPORT": lport
        }

        resp = self.client.call("module.execute", [self.command, self.argument, opts])
        self.logger.info("Handler setup response:", resp)

