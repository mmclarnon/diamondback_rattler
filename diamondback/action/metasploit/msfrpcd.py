import logging
import msgpack
import socket
import subprocess
import threading
import time
from diamondback.action import call_before_decorator,Action
from diamondback.support import add_inbound_accept_rule,ufw_allow_port,ufw_remove_port

class MsfRPC(Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.logger = logging.getLogger( 'msfrpc' )

        self.command = kwargs.get("command", 'exploit' )
        self.argument = kwargs.get("command_argument", "multi/handler" )

        self.payload = kwargs.get( "payload" )

        self.lport = kwargs.get("lport", 5555)
        self.container_name = kwargs.get("container", "metasploit")
        self.host = kwargs.get("host", self.get_local_ip_address() )
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
        self.rpc_connection = socket.create_connection((self.host, self.port))
        # Authenticate
        auth_req = {
            "method": "auth.login",
            "id": 1,
            "params": [self.user, self.password]
        }
        self.logger.info( auth_req )
        self.rpc_connection.sendall(msgpack.packb(auth_req))
        resp = msgpack.unpackb(self.rpc_connection.recv(4096), raw=False)
        self.logger.info( resp )
        if resp.get("result") == "success":
            self.token = resp.get("token")
            self.logger.info("Connected to msfrpcd, token acquired.")
        else:
            raise RuntimeError("Failed to authenticate to msfrpcd")

    def launch_msfrpcd(self):
        """
        Launch the Metasploit msfrpcd daemon inside the running container.
        """
        cmd = [
            "docker", "exec", self.container_name,
            "/usr/src/metasploit-framework/msfrpcd",
            "-U", self.user,
            "-P", self.password,
            "-S",
            "-a", "0.0.0.0",
            "-p", str(self.port),
            "-f"   # foreground mode so the process stays attached
        ]

        try:
            self.logger.info(f"Launching msfrpcd: {' '.join(cmd)}")
            # Use Popen so the daemon stays running and you can interact with it
            self.process = subprocess.Popen(cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            self.logger.info("msfrpcd daemon started successfully")

            # Helper to stream logs
            def stream_output(pipe, level="info"):
                for line in iter(pipe.readline, ''):
                    if line.strip():
                        getattr(self.logger, level)(f"[msfrpcd] {line.strip()}")
                pipe.close()

            # Start threads to capture stdout and stderr
            threading.Thread(target=stream_output, args=(self.process.stdout, "info"), daemon=True).start()
            threading.Thread(target=stream_output, args=(self.process.stderr, "error"), daemon=True).start()

            return self.process
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error starting msfrpcd: {e}")
            return None

    def run( self ):
        proc = self.launch_msfrpcd( )

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

        resp = self._send("module.execute", [self.command, self.argument, opts])
        self.logger.info("Handler setup response:", resp)

