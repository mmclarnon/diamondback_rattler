import logging
import multiprocessing
import random
import time

from diamondback.action import call_before_decorator,Action
from connection.ssh import SSHClientWrapped
from domain import Command

class SSHCommandExecution( Action ):
    def __init__( self, *args, **kwargs ):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'sshcommandexec' )
        self.logger.info( 'initializing SSHCmdExec action' )

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
        self.logger.info(f"\n[Process {multiprocessing.current_process().pid}] "
                f"Connecting to {self.get_input()}")
        host = self.get_input()
        try:
            # Create SSH client
            client = SSHClientWrapped( self.username, self.password, self.get_input(), port )
            
            self.logger.info(f"[{host}] Successfully connected")
            
            #commands = ['hostname', 'whoami', 'date', 'ps aux | head -5', 'echo "the hacker D1@m0ndB@ck was here" >> suspicious_file.txt']
            # Execute each command
            for command in commands:
                self.logger.info(f"[{host}] Executing: {command}")

                c = self.lookup_command( command, 'ssh' )
                if not c:
                    new_command         = Command( )
                    new_command.service = 'ssh'
                    new_command.value   = command
                    new_command.name    = command.split(" ")[0]

                    self.session.add( new_command )
                    self.session.commit( )

                r = client.execute( command,sudo=self.sudo )
                
                if r['out']:
                    self.logger.info(f"[{host}] Output:\n{r['out'][:200]}")  # Limit output length
                if r['err']:
                    self.logger.error(f"[{host}] Error: {r['err']}")
                
                time.sleep(random.randint(1,3))  # Small delay between commands
            
            # Close connection
            client.close()
            self.logger.info(f"[{host}] Connection closed")
        except Exception as e:
            self.logger.error(f"[{host}] Error: {str(e)}")

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
            self.logger.info(f"\nExecuting commands on host {self.get_input()}...")
            self.logger.info(f"Commands to execute: {list(commands)}\n")
            
            # Create a process for each host
            processes = []
            process = multiprocessing.Process(
                target=self.execute_commands_on_host,
                args=(list(commands), 22)
            )
            process.start()
            processes.append(process)
            
            # Wait for all processes to complete
            for process in processes:
                process.join()
            
            self.logger.info("\n✓ Command execution completed on all hosts")

        return self