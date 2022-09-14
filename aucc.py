import nmap
import os
import sys
import argparse
import subprocess
def print_current(ip, port):
    print ("Target IP: "+ip, end="")
    if (port != -1 ):
        print ("|| Port Range: "+port)
    print()
    
def remove():
    tput = subprocess.Popen(['tput','cols'], stdout=subprocess.PIPE)
    cols = int(tput.communicate()[0].strip())
    print("\033[A{}\033[A".format(' '*cols))
   

def nmapscan():
    os.system('clear')
    print('----------------------------------------------------')
    print("\t\tRunning nmap scan")
    print('----------------------------------------------------')
    ip_data = input("\nEnter target IP address: \n >> ")
    remove()
    remove()
    print_current(ip_data,-1)
    nm = nmap.PortScanner()
    nm.scan(str(ip_data),  arguments='-O -sV')
    print("Runned command: \""+ nm.command_line()+"\"")
    
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
    
            lport = nm[host][proto].keys()
            sorted(lport)
            for port in lport:
                print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

    if ('osmatch' in nm[ip_data]):
        for osclass in nm[ip_data]['osmatch'][0]["osclass"]:
            print("Type : {0}".format(osclass["type"]), end=" | ")
            print('vendor : {0}'.format(osclass['vendor']), end=" | ")
            #print('osfamily : {0}'.format(osclass['osfamily']), end=" ")
            print('osgen : {0}'.format(osclass['osgen']), end="")
            print('~%{0}'.format(osclass['accuracy']), end=" | ")
            print('{0}'.format(osclass['cpe'][0]), end=" ")
            print('')


    print('----------------------------------------------------')
    if (nm[ip_data].has_tcp(80)):
        print ("Perhaps, there is a website, check it. You can inspect source code or fuzz.")
        print('----------------------------------------------------')
        fuzzdir(ip_data)

def fuzzdir(ip_data):    
    if (input("If you want to fuzz with gobuster type \"fuzz\"  and press enter\n") == "fuzz"):
        temp = input("Which path(default /): ")
        print("Running command: gobuster dir -u http://" + ip_data+ temp + " -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 150")
        os.system("gobuster dir -u http://"+ ip_data+ temp +"/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100 -q -n -e")
        

    
def main():
    parser=argparse.ArgumentParser(
        description="""Welcome to our tool, all information given below.""",
        epilog="""""")
    parser.add_argument('--advanced', default=False, help='advanced functions',action="store_true")
    args=parser.parse_args()
    
    if (args.advanced):
        print ("hello")

    func = input("""Choose the option you need:
    a) Enumerate the target
    b) Encryption/Decryption\nYour option: """)
    if (func == "a"):
        nmapscan()
        
    elif(func == "b"):
        endecryption()
    
    
if __name__=="__main__":
    main()