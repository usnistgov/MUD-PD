#! /usr/bin/python3

import hashlib

#MySQl libraries
import mysql.connector
from mysql.connector import MySQLConnection, Error
from configparser import ConfigParser

import os
import pyshark


class CaptureDatabase:


    '''    
    def __init__(self, *initial_data, **kwargs):
        for dictionary in initial_data:
            for key in dictionary:
                setattr(self, key, dictionary[key])
        for key in kwargs:
            setattr(self, key, kwargs[key])
    '''
    def __init__(self, db_config):
        try:
            print("Connecting to MySQL database...")
            self.conn = mysql.connector.connect(**db_config)

            if self.conn.is_connected():
                print("connection established.")
            else:
                print("connection failed.")

        except Error as error:
            print(error)
        #finally:
        #    self.conn.close()
        #    print("Connection closed.")

    def __exit__(self):
        self.conn.close()
        print("Connection closed.")

    #def connect(self, 
'''
def connect():
    # Connect to MySQL database
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            passwd="MudDB123!",
            database="DeviceCaptures")

        if conn.is_connected():
            print("Connected to MySQL database")
    except Error as e:
        print(e)
    finally:
        conn.close()
'''

def read_db_config(filename='config.ini', section='mysql'):
    parser = ConfigParser()
    parser.read(filename)

    db = {}
    if parser.has_section(section):
        items = parser.items(section)
        for item in items:
            db[item[0]] = item[1]
    else:
        raise Exception('{0} not found in the {1} file'.format(section, filename))

    return db

def connect():
    # Connect to MySQL database
    db_config = read_db_config()

    try:
        print("Connecting to MySQL database...")
        conn = mysql.connector.connect(**db_config)

        if conn.is_connected():
            print("connection established.")
        else:
            print("connection failed.")

    except Error as error:
        print(error)
    finally:
        conn.close()
        print("Connection closed.")

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

    #def __del__(self):
    def __exit__(self):
        self.cap.close()


# Tools for collecting information ***
# MAC Address Lookup
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

# Hostname Lookup
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


# Database Main (for testing purposes)
if __name__== "__main__":

    connect()

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
        break

    print("Unique DST IP addresses:")
    for ip in capture.uniqueIP_dst:
        lookup_hostname(ip)
        print(ip + "\n")
        break

    print("\n\nUnique DST IPv6 addresses:")
    for ipv6 in capture.uniqueIPv6_dst:
        lookup_hostname(ipv6)
        print(ipv6 + "\n")
        break

    mac = "BC:92:6B:A0:00:01"
    company = lookup_mac(mac)
    
    ip_addr = "216.220.61.236"
    lookup_hostname(ip_addr)


#Adding capture things items:
    #fileName
    #fileLoc - manually input to generate filename, md5, and capDate
    #md5
    #capDate
    #Activity - manual
    #Details - manual

#Adding device items:
    #Mfr - attempt to generate from MAC
    #Model - manual
    #MAC_addr - Can be located in MAC address
    #internalName - manual
    #Device category - manual
    #MUD capable - may be able to generate this, but manual for now
    #wifi #if MAC found, then wifi is set to YES
    #bluetooth - manual
    #zigbee - manual
    #zwave - manual
    #4G - manual
    #5G - manual
    #other protocols - manual
    #notes - manual

#Adding Device State items:
    #md5 - generated from input fileLoc
    #MAC address - identified from file
    #internal name (previously given)
    #fw_ver - manual
    #ipv4_addr - generated from file
    #ipv6_addr - generated from file

#Adding Protocol items:
    #md5 - generated from input fileLoc
    #MAC address - generated from file
    #src_port - generated from input file
    #dst_ip_addr - generated from file
    #ipv6 (bool) - generated from file
    #dst_url - generated from file
    #dst_port - generated from file
    #notes - generated
