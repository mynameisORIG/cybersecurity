#! /usr/bin/python3
#from lib.enum.arguments import argNmap
import nmap
import subprocess
import shlex

nmap = nmap.PortScanner()

class argNmap():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-ip", type=str, required=True, help="IP or hostname you wish to scan")
    args = parser.parse_args()
#argNmap()

def nmapPreReq():
    global victimPortsList
    victimPortsList = []

    global victim
    # victim = nmap.scan(argNmap.args.ip, 
    #     arguments=f"-sC -sV -T4 -Pn -p- -oN files/nmap/{argNmap.args.ip}.nmap")
    victim = nmap.scan(argNmap.args.ip)

class protocols:
    def http():
        wordlist = {
            'common' : '/usr/share/wordlists/dirb/common.txt'
        }
        # gobusterFile = f'files/gobuster/{argNmap.args.ip}-{ports}.gbuster'
        web_enum_file = f'files/web_enum/{argNmap.args.ip}-{ports}.fbuster'
        commands = {
            'feroxbuster' : f'feroxbuster -u http://{argNmap.args.ip}:{ports} -w ' + wordlist['common'] + f' -s 200 -d 1',
            # 'gobuster' : f'gobuster dir -u http://{argNmap.args.ip}:{ports} -w ' + wordlist['commons'] + f' -t 50 -o {web_enum_file}',
            'nikto' : f'nikto -h {argNmap.args.ip}:{ports}'

        }
        for cmds in commands.values():
            subprocess.run(shlex.split(cmds))

    def ftp():
        # print('still working on ftp\n')
        from ftplib import FTP
        ftp = FTP(argNmap.args.ip)
        # this logins as anonymous with password anonymous
        ftp.login(user='anonymous', passwd='anonymous')
        ftp.retrlines('LIST')
        # try:
        #     ftp.dir()
        # except FTP.error_perm as resp:
        #     if str(resp) == "530 Permission denied":
        #         pass

    def mountd():
        showmount = subprocess.run(['showmount', '-e', f'{argNmap.args.ip}'], stdout=subprocess.PIPE)
        if showmount.stdout == f'Export list for {argNmap.args.ip}':
            subprocess.run(['mount',
                            '-t',
                            'nfs', 
                            f'{argNmap.args.ip}:{showmount.stdout[31:40]}, /mnt'], stdout=subprocess.PIPE)

    def domain():
        subprocess.run(['dnsrecon', 
                            '-r', 
                            '127.0.0.0/24', 
                            '-n',
                            f'{argNmap.args.ip}',
                            '-d', 
                            'blah'])
    def smb():
        print(f'Running smbclient on port {ports}\n')
        subprocess.run(['smbclient', 
                        '-NL', 
                        f'//{argNmap.args.ip}',
                        '-R'])
def nmapifElsePorts():
    import mmap
    victimPortsList = list(nmap[argNmap.args.ip]['tcp'].keys())

    global ports
    for ports in victimPortsList:
        #print(nmap[argNmap.args.ip]['tcp'][ports]['name'])
        portName = nmap[argNmap.args.ip]['tcp'][ports]['name']
        # gobuster's any http sites
        if portName == 'http':
            protocols.http()
        elif portName == 'ftp':
            protocols.ftp()
        elif portName == 'mountd':
            protocols.mountd()
        elif portName == 'domain':
            protocols.domain()
        elif portName == 'smbd' or 'netbios-ssn':
            protocols.smb()
        elif portName == 'telnet':
            print('do something with telnet')



def main():
    nmapPreReq()
    nmapifElsePorts()

if __name__ == '__main__':
    main()