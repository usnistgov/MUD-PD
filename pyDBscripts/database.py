#! /usr/bin/python3

import hashlib
import mysql.connector
import os
import pyshark

'''
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="MudDB123!",
  database="DeviceCaptures"
)

mycursor = mydb.cursor()
'''
class CaptureDigest:
    def __init__(self, fpath):
        self.fdir, self.fname = os.path.split(fpath)
        self.md5hash = hashlib.md5(open(fpath,'rb').read()).hexdigest()
        self.cap = pyshark.FileCapture(fpath)
        self.capDate = self.cap[0].sniff_timestamp

        self.uniqueIP = []
        self.uniqueIPv6 = []
        self.uniqueMAC = []

        self.uniqueIP_dst = []
        self.uniqueIPv6_dst = []

        self.cap.apply_on_packets(self.id_unique_addrs)
        #self.id_unique_addrs()
        
    def print_init(self):
        print(self.fname)
        print(self.fdir)
        print(self.md5hash)
        print(self.capDate)
        
#    def id_unique_addrs(self):
#        for pkt in self.cap:
    def id_unique_addrs(self, pkt):
        # Try to get packet IP address
        try:
            pIP = pkt.ip.src
        except:
            # Check if IPv6 address
            try:
                pIPv6 = pkt.ipv6.src
            except:
                pass
            else:
                if pIPv6 not in self.uniqueIPv6:
                    #print(pIPv6)
                    self.uniqueIPv6.append(pIPv6)
        else:
            # Add unique IPs to the list
            if pIP not in self.uniqueIP:
                #print(pIP)
                self.uniqueIP.append(pIP)

        # Try to get the MAC address
        try:
            pMAC = pkt.eth.src
        except:
            pMAC = pkt.sll.src_eth

        if pMAC not in self.uniqueMAC:
            #print(pMAC)
            self.uniqueMAC.append(pMAC)


        # Try to get destination IP address
        try:
            pIP_dst = pkt.ip.dst
        except:
            # Check if IPv6 address
            try:
                pIPv6_dst = pkt.ipv6.dst
            except:
                pass
            else:
                if pIPv6_dst not in self.uniqueIPv6_dst:
                    #print(pIPv6)
                    self.uniqueIPv6_dst.append(pIPv6_dst)
        else:
            # Add unique IPs to the list
            if pIP_dst not in self.uniqueIP_dst:
                #print(pIP)
                self.uniqueIP_dst.append(pIP_dst)

    def __del__(self):
        self.cap.close()


import json
import requests
def lookup_mac(mac):
    MAC_URL = 'http://macvendors.co/api/%s'
    r = requests.get(MAC_URL % mac)
    try:
        company = json.loads(r.text)['result']['company']
    except:
        print("**company not found**")
        return "**company not found**"
    else:
        print(company)
        return company


import socket
def lookup_hostname(ip_addr):
    try:
        r = socket.gethostbyaddr(ip_addr)
    except socket.herror as serr:
        if serr.errno != 1:
            print(exception)
        else:
            print("**unknown host**")
            return "**unknown host**"
    except Exception as exception:
        print(exception)
    else:
        print(r[0])
        return r[0]

if __name__== "__main__":
    fname = "/Users/ptw/Documents/GRA-MITRE-DDoS/captures/ecobee/ecobeeThermostat_iphone_setup.pcap"
    capture = CaptureDigest(fname)
    #import_file(fname)
    capture.print_init()
    print("Unique IP addresses:")
    print(*capture.uniqueIP, sep="\n")
    print("\n\nUnique IPv6 addresses:")
    print(*capture.uniqueIPv6, sep="\n")
#    print("\n\nUnique MAC addresses:")
#    print(*capture.uniqueMAC, sep="\n")
    print("\n")

    for mac in capture.uniqueMAC:
        lookup_mac(mac)
        print(mac + "\r\n")

    print("Unique DST IP addresses:")
    for ip in capture.uniqueIP_dst:
        lookup_hostname(ip)
        print(ip + "\n")

    print("\n\nUnique DST IPv6 addresses:")
    for ipv6 in capture.uniqueIPv6_dst:
        lookup_hostname(ipv6)
        print(ipv6 + "\n")

    mac = "BC:92:6B:A0:00:01"
    company = lookup_mac(mac)
    
    ip_addr = "216.220.61.236"
    lookup_hostname(ip_addr)
