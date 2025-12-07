import logging
import traceback
import sys
import os
import ntpath
import cmd
import time
import logging
from base64 import b64encode

from diamondback.domain import *
from diamondback.connection import *
from diamondback.util import get_netbios_name

from impacket.smbconnection import SMBConnection as ISMBConnection, SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL

OUTPUT_FILENAME = '__' + str(time.time())
CODEC = sys.stdout.encoding

def load_smbclient_auth_file(path):
    '''Load credentials from an smbclient-style authentication file (used by
    smbclient, mount.cifs and others).  returns (domain, username, password)
    or raises AuthFileSyntaxError or any I/O exceptions.'''

    lineno = 0
    domain = None
    username = None
    password = None
    for line in open(path):
        lineno += 1

        line = line.strip()

        if line.startswith('#') or line == '':
            continue

        parts = line.split('=', 1)
        if len(parts) != 2:
            raise AuthFileSyntaxError(path, lineno, 'No "=" present in line')

        (k, v) = (parts[0].strip(), parts[1].strip())

        if k == 'username':
            username = v
        elif k == 'password':
            password = v
        elif k == 'domain':
            domain = v
        else:
            raise AuthFileSyntaxError(path, lineno, 'Unknown option %s' % repr(k))

    return (domain, username, password)

class SMBConnection( Connection ):
    def __init__( self, target_address, username, password, port=135 ):
        super().__init__( target_address, username, password )  # Call the abstract class's __init__
        self.logger = logging.getLogger( 'smbconnection' )
        self.set_connection_type( 'smb' )
        self.set_port( port )
        self.__output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = str('')        
        self.__username = username
        self.__password = password
        self.__domain = ''
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = ''
        self.__share = 'ADMIN$'
        self.__noOutput = False
        self.__doKerberos = False
        self.__kdcHost = ''
        self.__remoteHost = ''
        self.__pwd = str('C:\\')
        self.__output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = str('')
        self.__shell = 'cmd.exe /Q /c '
        self.__shell_type = None
        self.__pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
        self.__silentCommand = False
        self.__pwd = str('C:\\')
        self.__noOutput = True

    def execute( self, command, sudo=False, shell_type='cmd' ):
        if shell_type == 'powershell':
            command = '$ProgressPreference="SilentlyContinue";' + command
            command = self.__pwsh + b64encode(command.encode('utf-16le')).decode()

        command = self.__shell + command

        if self.__noOutput is False:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output + ' 2>&1'
        response = self.__win32Process.Create(command, self.__pwd, None)

        if self.__noOutput is False:
            self.get_output()     

    def open( self ):
        ct = self.get_connection_type( )
        t = self.get_target()
        try:
            self.logger.info( f'opening {ct} connection to {t} as {self.get_username()}' )

            smbConnection = ISMBConnection( t, t )
            if self.__doKerberos is False:
                smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                self.logger.info( 'smbConnection login' )
            else:
                smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                            self.__nthash, self.__aesKey, kdcHost=self.__kdcHost)


            dcom = DCOMConnection(t, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                    self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost, remoteHost=t)
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
            self.__win32Process, _ = iWbemServices.GetObject('Win32_Process')
            self.logger.info( 'DComConnection established...' )
            self.set_client( smbConnection )
            smbConnection.setTimeout(100000)
            self.dcom = dcom
            shares = smbConnection.listShares()
            self.logger.info(f"Found {len(shares)} shares:")
            self.iWbemLevel1Login = iWbemLevel1Login

            self.do_cd('\\')
            
            dialect = smbConnection.getDialect()
            if dialect == SMB_DIALECT:
                self.logger.info("SMBv1 dialect used")
            elif dialect == SMB2_DIALECT_002:
                self.logger.info("SMBv2.0 dialect used")
            elif dialect == SMB2_DIALECT_21:
                self.logger.info("SMBv2.1 dialect used")
            else:
                self.logger.info("SMBv3.0 dialect used")
            self.logger.info( 'opened' )
            self.connection_state = ConnectionState.CONNECTED
        except:
            tb = traceback.format_exc()
            self.get_errors().append( tb )
            self.logger.error( 'ERROR: unable to open connection? check error logs' )
            self.connection_state = ConnectionState.ERROR
        return self
    
    def put_file( self, local_path=None, remote_path=None ):
        try:
            src_path = local_path
            dst_path = remote_path

            src_file = os.path.basename(src_path)
            fh = open( src_path, 'rb' )
            dst_path = dst_path.replace('/', '\\')
            pathname = ntpath.join(ntpath.join(self.__pwd, dst_path))
            drive, tail = ntpath.splitdrive(pathname)
            drive = "C:"
            print( tail )
            self.logger.info("Uploading %s to %s" % (src_file, pathname))
            print( drive[:-1]+'$' )
            self.get_client().putFile(drive[:-1] + '$', tail, fh.read)
            fh.close()
        except Exception as e:
            logging.critical(str(e))
            pass

    def do_cd(self, s):
        self.execute('cd ' + s)
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            self.__outputBuffer = ''
        else:
            self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s))
            self.execute('cd ')
            self.__pwd = self.__outputBuffer.strip('\r\n')
            self.prompt = (self.__pwd + '>')
            if self.__shell_type == 'powershell':
                self.prompt = 'PS ' + self.prompt + ' '
            self.__outputBuffer = ''
        print( self.__pwd )

    def get_output( self ):
        def output_callback(data):
            try:
                print( data )
                self.__outputBuffer += data.decode(CODEC)
            except UnicodeDecodeError:
                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute wmiexec.py '
                              'again with -codec and the corresponding codec')
                print( data )
                self.__outputBuffer += data.decode(CODEC, errors='replace')

        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        while True:
            try:
                self.get_client().getFile(self.__share, self.__output, output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    # Output not finished, let's wait
                    time.sleep(1)
                    pass
                elif str(e).find('Broken') >= 0:
                    # The SMB Connection might have timed out, let's try reconnecting
                    logging.debug('Connection broken, trying to recreate it')
                    self.get_client().reconnect()
                    return self.get_output()
        self.get_client().deleteFile(self.__share, self.__output)

    def get_file( self, src_path ):
        try:
            newPath = ntpath.normpath(ntpath.join(self.__pwd, src_path))
            drive, tail = ntpath.splitdrive(newPath)

            filename = ntpath.basename(tail)
            fh = open(filename, 'wb')
            self.logger.info("Downloading %s\\%s" % (drive, tail))
            self.get_client().getFile('C$', tail, fh.write)
            fh.close()
        except Exception as e:
            logging.error(str(e))

            if os.path.exists(filename):
                os.remove(filename)        

    def close( self ):
        t = self.get_target( )
        self.logger.info( f'closing connection to {t}' )
        self.__win32Process = None
        self.get_client().close( )
        self.dcom.disconnect( )
        try:
            self.iWbemLevel1Login.disconnect( )
        except:
            pass
        self.connection_state = ConnectionState.CLOSED
        return self
    
    def __del__( self ):
        self.logger.info( 'connection deconstructor firing..' )
        if self.connection_state != ConnectionState.CLOSED:
            try:
                if self.get_client():
                    self.logger.info( 'calling paramiko specific close() now' )
                    self.get_client().close( )
                    self.dcom.disconnect( )
                    try:
                        self.iWbemLevel1Login.disconnect( )
                    except:
                        pass
            except:
                self.logger.warning( 'quietly handling exception closing paramiko connection' )

            self.connection_state = ConnectionState.CLOSED
            self.logger.info( 'marking connection as closed.' )
        else:
            self.logger.info( 'connection is closed...' )

if __name__ == "__main__":
    c = SMBConnection( '10.0.0.196', 'developer', 'PASSWORD' )
    c.open( )
    print( c.connection_state )
    c.put_file( "/tmp/test.txt", "waldo.txt" )
    c.get_file( "waldo.txt" )
    c.close( )