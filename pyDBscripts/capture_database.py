#! /usr/bin/python3

import hashlib

#MySQl libraries
from configparser import ConfigParser
from datetime import datetime
from lookup import *
import mysql.connector
from mysql.connector import MySQLConnection, Error
import os
import pyshark

class CaptureDatabase:
    

    add_capture = ("INSERT INTO capture "
                        # TEXT      TEXT     BINARY(32)   DATETIME TEXT      TEXT
                        "(fileName, fileLoc, fileHash, capDate, activity, details) "
                        #"VALUES (%s, %s, %s, %s, %s, %s);")
                        "VALUES (%(fileName)s, %(fileLoc)s, %(fileHash)s, %(capDate)s, %(activity)s, %(details)s);")

    add_device_in_capture = ("INSERT INTO device_in_capture "
                             # TEXT      VARCHAR   VARCHAR
                             "(fileName, fileHash, mac_addr) "
                             "VALUES (%(fileName)s, %(fileHash)s, %(mac_addr)s);")

    add_device = ("INSERT INTO device "
                       # TEXT TEXT   VARCHAR       VARCHAR   TEXT            BOOL       BOOL BOOL BOOL BOOL BOOL       BOOL    BOOL   TEXT            TEXT
                       "(mfr, model, internalName, mac_addr, deviceCategory, mudCapable, wifi, 3G, 4G, 5G,  bluetooth, zigbee, zwave, otherProtocols, notes) "
                       #"VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
                       "VALUES (%(mfr)s, %(model)s, %(internalName)s, %(mac_addr)s, %(deviceCategory)s, %(mudCapable)s, %(wifi)s, %(G3)s, %(G4)s, %(G5)s, %(bluetooth)s, %(zigbee)s, %(zwave)s, %(otherProtocols)s, %(notes)s)")

    add_device_state = ("INSERT INTO device_state "
                             # BINARY       VARCHAR   VARCHAR       TEXT    VARCHAR    TEXT
                             "(fileHash, mac_addr, internalName, fw_ver, ipv4_addr, ipv6_addr) "
                             #"VALUES (%s, %s, %s, %s, %s, %s);"
                             "VALUES (%(fileHash)s, %(mac_addr)s, %(internalName)s, %(fw_ver)s, %(ipv4_addr)s, %(ipv6_addr)s);")

    add_protocol = ("INSERT INTO protocol "
                         # BINARY       VARCHAR   TEXT      INT       TEXT         BOOL  TEXT     INT       TEXT
                         "(fileHash, mac_addr, protocol, src_port, dst_ip_addr, ipv6, dst_url, dst_port, notes) "
                         #"VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);")
                         "VALUES (%(fileHash)s, %(mac_addr)s, %(protocol), %(src_port)s, %(dst_ip_addr)s, %(ipv6)s, %(dst_url)s, %(dst_port)s, %(notes)s);")

    # Queries
    query_unique_capture = ("SELECT fileHash FROM capture;")

    query_imported_capture = ("SELECT * FROM capture;")

    #query_device_from_capture = ("SELECT * FROM device WHERE fileName=%s;")
    #query_device_from_capture = ("SELECT * FROM device_in_capture WHERE fileHash=%s;")
    query_device_from_capture = ("SELECT * FROM device WHERE mac_addr = ANY "
                                 "(SELECT mac_addr FROM device_in_capture WHERE"
                                 #" fileHash=%s);"
                                 " fileName=%s);")

    #query_known_devices_from_capture = ("SELECT * FROM device_in_capture "
    #                                    "WHERE fileHash = %s AND mac_addr = %s;")
    query_known_devices_from_capture = ("SELECT mac_addr FROM device_in_capture "
                                        "WHERE fileHash = %s;")

    query_most_recent_fw_ver = ("SELECT ds.fw_ver FROM device_state AS ds "
                                "INNER JOIN "
                                "    (SELECT capture.fileHash as fileHash "
                                "     FROM capture "
                                "     INNER JOIN "
                                "         (SELECT MAX(c.capDate) as capDate "
                                "          FROM device_state as ds "
                                "          INNER JOIN "
                                "              capture as c on ds.fileHash = c.fileHash "
                                "          WHERE ds.mac_addr = %(mac_addr)s AND "
                                "                c.capDate <= %(capDate)s "
                                "         ) AS q1 ON capture.capDate=q1.capDate "
                                "     ) AS q2 ON ds.fileHash=q2.fileHash "
                                " WHERE ds.mac_addr = %(mac_addr)s;")

    query_devices =  ("SELECT * FROM device;")

    query_device_info =  ("SELECT * FROM device WHERE mac_addr=%s;")

    query_device_macs = ("SELECT mac_addr FROM device;")

    query_device_state = ("SELECT * FROM device_state WHERE fileHash=%s AND mac_addr=%s;")

    query_device_state_exact = ("SELECT * FROM device_state WHERE "
                                " fileHash=%(fileHash)s AND mac_addr=%(mac_addr)s AND "
                                " internalName=%(internalName)s AND fw_ver=%(fw_ver)s AND "
                                " ipv4_addr=%(ipv4_addr)s AND ipv6_addr=%(ipv6_addr)s;")
    
    query_device_communication = ("SELECT * FROM protocol WHERE device=%s;")

    query_device_strings = ("SELECT * FROM strings WHERE device=%s;")
    
    def __init__(self, db_config):
        try:
            print("Connecting to MySQL database...")
            self.cnx = mysql.connector.connect(**db_config)

            if self.cnx.is_connected():
                print("connection established.")
            else:
                print("connection failed.")

        except Error as error:
            print(error)
        #finally:
        #    self.cnx.close()
        #    print("Connection closed.")

        self.cursor = self.cnx.cursor(buffered=True)

    # SQL Insertion Commands
    def insert_capture(self, data_capture):
        #self.cap = CaptureDigest(data_capture.get(fpath, "none"))

        self.cursor.execute(self.add_capture, data_capture)
        self.cnx.commit()

    def insert_device(self, data_device):
        self.cursor.execute(self.add_device, data_device)
        self.cnx.commit()

    def insert_device_in_capture(self, data_device_in_capture):
        self.cursor.execute(self.add_device_in_capture, data_device_in_capture)
        self.cnx.commit()

    def insert_device_state(self, data_device_state):
        self.cursor.execute(self.add_device_state, data_device_state)
        self.cnx.commit()

    def insert_protocol(self, data_protocol):
        self.cursor.execute(self.add_protocol, data_protocol)
        self.cnx.commit()

    # SQL Query Commands
    def select_unique_captures(self):
        self.cursor.execute(self.query_unique_capture)

    def select_imported_captures(self):
        self.cursor.execute(self.query_imported_capture)

    def select_devices_from_cap(self, capture):
        #print(capture)
        self.cursor.execute(self.query_device_from_capture, (capture,))

    def select_known_devices_from_cap(self, fileHash):
        self.cursor.execute(self.query_known_devices_from_capture, (fileHash,))

    def select_most_recent_fw_ver(self, macdatemac):
        self.cursor.execute(self.query_most_recent_fw_ver, macdatemac)

    def select_devices(self):
        self.cursor.execute(self.query_devices)
    
    def select_device(self, mac):
        self.cursor.execute(self.query_device_info, (mac,))

    def select_device_state(self, hash, mac):
        self.cursor.execute(self.query_device_state, (hash, mac))

    def select_device_state_exact(self, device_state_data):
        self.cursor.execute(self.query_device_state_exact, device_state_data)

    def select_device_macs(self):
        self.cursor.execute(self.query_device_macs)                                                                                

    def select_device_communication(self, device):
        self.cursor.execute(self.query_device_communication, device)

    def select_device_strings(self, device):
        self.cursor.execute(self.query_device_strings, device)

    def __exit__(self):
        self.cursor.close()
        self.cnx.close()
        print("Connection closed.")


'''
from configparser import ConfigParser
#import json
#import requests
#import socket
class DatabaseHandler:


    def __init__(self, filename='config.ini', section='mysql'):

        try:
            self.config = read_db_config(filename, section)
        except:
            self.config = {"host": "", "database" : "", "user" : "", "passwd" : ""}

    def read_db_config(self, filename='config.ini', section='mysql'):
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

    def save_db_config(self, filename='config.ini', section='mysql'):
        f = open(filename, "w")
        f.write("[{%s}]", section)
        for key,val in self.db_config:
            f.write("\n{%s} = {%s}", key, val)
        f.close()
        
    def db_connect(self, entries):
        db_config = {}

        for entry in entries:
            field = entry[0]
            text  = entry[1].get()
            db_config[field] = text
            print('%s: "%s"' % (field, text)) 

        self.db = CaptureDatabase(db_config)

    def __exit__(self):
        self.db.__exit__()
#'''

class CaptureDigest:


    def __init__(self, fpath):
        self.fdir, self.fname = os.path.split(fpath)
        self.fileHash = hashlib.md5(open(fpath,'rb').read()).hexdigest()
        self.cap = pyshark.FileCapture(fpath)
        self.capTimeStamp = self.cap[0].sniff_timestamp
        #self.capDate = self.cap[0].sniff_timestamp
        #(self.capDate, self.capTime) = self.cap[0].sniff_timestamp.split()
        (self.capDate, self.capTime) = datetime.utcfromtimestamp(float(self.capTimeStamp)).strftime('%Y-%m-%d %H:%M:%S').split()

        print(self.capDate)
        print(self.capTime)

        self.uniqueIP = []
        self.uniqueIPv6 = []
        self.uniqueMAC = []

        self.ip2mac = {}

        self.uniqueIP_dst = []
        self.uniqueIPv6_dst = []

        self.cap.apply_on_packets(self.id_unique_addrs)
        #self.id_unique_addrs()
        
    def print_init(self):
        print(self.fname)
        print(self.fdir)
        print(self.fileHash)
        print(self.capDate)
        
#    def id_unique_addrs(self):
#        for pkt in self.cap:

    def findIP(self, mac, v6=False):
        if v6:
            if (mac, "ipv6") in self.ip2mac:
                ip = self.ip2mac[(mac, "ipv6")]
            else:
                ip = "Not found"
        else:
            if (mac, "ipv4") in self.ip2mac:
                ip = self.ip2mac[(mac, "ipv4")]
            else:
                ip = "Not found"

        return ip

    def id_unique_addrs(self, pkt):
        # Try to get the MAC address
        try:
            pMAC = pkt.eth.src
        except:
            pMAC = pkt.sll.src_eth

        if pMAC not in self.uniqueMAC:
            #print(pMAC)
            self.uniqueMAC.append(pMAC)

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
                if (pMAC, "ipv6") not in self.ip2mac:
                    self.ip2mac[(pMAC, "ipv6")] = pIPv6
                if pIPv6 not in self.uniqueIPv6:
                    #print(pIPv6)
                    self.uniqueIPv6.append(pIPv6)
        else:
            if (pMAC, "ipv4") not in self.ip2mac:
                self.ip2mac[(pMAC, "ipv4")] = pIP
            # Add unique IPs to the list
            if pIP not in self.uniqueIP:
                #print(pIP)
                self.uniqueIP.append(pIP)


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
