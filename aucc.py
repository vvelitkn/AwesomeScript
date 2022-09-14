import nmap
import os
from string import ascii_lowercase, ascii_lowercase, ascii_lowercase, ascii_uppercase, ascii_uppercase, ascii_uppercase, ascii_letters
import string
import sys
import argparse
import subprocess
import urllib
from bs4 import BeautifulSoup
from urllib.request import urlopen
from urllib.parse import urlsplit
import re

ext = set()
def getInExt(url):
    o = urllib.parse.urlsplit(url)
    html = urlopen(url)
    bs = BeautifulSoup(html, 'html.parser')
    for link in bs.find_all('a', href = re.compile('^((https://)|(http://)|())')):
        if 'href' in link.attrs:
            if o.netloc in (link.attrs['href']):
                ext.add(link.attrs['href'])
            #    continue
            else:
                ext.add(link.attrs['href'])

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
        if (input("If you want to fuzz with gobuster type \"fuzz\"  and press enter\n") == "fuzz"):
            fuzzdir(ip_data)
            remove()
            remove()
    if (nm[ip_data].has_tcp(21)):
        print("Check if there is anonymous login FTP")
    if (nm[ip_data].has_tcp(139) or nm[ip_data].has_tcp(445)):
        print("Check if there is public samba share")

def fuzzdir(ip_data):    
    remove()
    remove()
    print("Which path (default /): ", end="")
    temp = input()
    remove()
    print("Running command: gobuster dir -u http://" + ip_data+ temp + " -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 150")
    os.system("gobuster dir -u http://"+ ip_data+ temp +" -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100 -q -n -e")
   
def endecryption():
    os.system("clear")
    print("""a) Base64 decryption
b) Base64 encryption
c) ROT encryption/encryption
d) Hash identifier""")
    choice = input("Your choice: ")
    os.system("clear")
    if (choice=="a"): 
        temp = input("Enter the text: ")
        os.system("echo "+temp+" | base64 --decode")
    elif (choice=="b"): 
        temp = input("Enter the text: ")
        os.system("echo "+temp+" | base64")
    elif (choice=="c"): 
        message = input("Enter the text: ")
        for key in range (1,25):
            s = ""
            upperalphabet = ascii_uppercase
            loweralphabet = ascii_lowercase
            for letter in message:
                if letter in " ~`!@#$%^&*()+_-={}|[]\:;,./<>?":
                    s = s + letter
                elif letter in string.ascii_uppercase:
                    s = s + upperalphabet[(upperalphabet.index(letter) + key) % 26]  # %62 is used to make the list cyclic
                elif letter in string.ascii_lowercase:
                    s = s + loweralphabet[(loweralphabet.index(letter) + key) % 26 ]
                else:
                    s =s+ letter
            print(str(key) +". iteration:\t"+s)

    
    
     
def exturls():
    os.system("clear")
    ip_data = input("\nEnter target IP address: \n >> ")
    print('----------------------------------------------------')
    print ("Scraping everything...")
    print('----------------------------------------------------')

    getInExt("http://"+ip_data+"/")
    
    for i in ext:
        print(i)
    
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
    b) Encryption/Decryption
    c) Enumarate external/internal links
    Your option: """)
    if (func == "a"):
        nmapscan()
        
    elif(func == "b"):
        endecryption()
    
    elif(func == "c"):
        exturls()
    
if __name__=="__main__":
    main()