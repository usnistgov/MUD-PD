#! /usr/bin/python3

import hashlib

#MySQl libraries
from configparser import ConfigParser
from datetime import datetime
#from lookup import *
from src.lookup import *
import mysql.connector
from mysql.connector import MySQLConnection, Error
import os
import pyshark
import subprocess

class CaptureDatabase:


    new_database = (
        "CREATE DATABASE ")

    drop_tables = (
        "DROP TABLE IF EXISTS "
        "    capture, "
        "    device_in_capture, "
        "    mac_to_mfr, "
        "    device, "
        "    device_state, "
        "    packet, "
        "    protocol;")
    
    create_capture = (
        "CREATE TABLE capture ( "
        "    id INT PRIMARY KEY AUTO_INCREMENT, "
        "    fileName TEXT, "
        "    fileLoc TEXT, "
        "    fileHash CHAR(64) UNIQUE, "
        "    capDate DATETIME, "
        "    capDuration INT, "
        "    activity TEXT, "
        "    details TEXT);")

    create_device_in_capture = (
        "CREATE TABLE device_in_capture ( "
        "    id INT PRIMARY KEY AUTO_INCREMENT, "
        "    fileName TEXT, "
        "    fileHash CHAR(64), "
        "    mac_addr VARCHAR(17));")

    create_mac_to_mfr = (
        "CREATE TABLE mac_to_mfr ( "
        "    id INT PRIMARY KEY AUTO_INCREMENT, "
        "    mac_prefix VARCHAR(8) UNIQUE, "
        "    mfr TEXT);")

    create_device = (
        "CREATE TABLE device ( "
        "    id INT PRIMARY KEY AUTO_INCREMENT, "
        "    mfr TEXT DEFAULT NULL, "
        "    model TEXT DEFAULT NULL, "
        "    mac_addr VARCHAR(17) UNIQUE, "
        "    internalName VARCHAR(20) UNIQUE DEFAULT NULL, "
        "    deviceCategory TEXT DEFAULT NULL, "
        "    mudCapable BOOL DEFAULT FALSE, "
        "    wifi BOOL DEFAULT FALSE, "
        "    ethernet BOOL DEFAULT FALSE, "
        "    bluetooth BOOL DEFAULT FALSE, "
        "    3G BOOL DEFAULT FALSE, "
        "    4G BOOL DEFAULT FALSE, "
        "    5G BOOL DEFAULT FALSE, "
        "    zigbee BOOL DEFAULT FALSE, "
        "    zwave BOOL DEFAULT FALSE, "
        "    otherProtocols TEXT DEFAULT NULL, "
        "    notes TEXT DEFAULT NULL, "
        "    unidentified BOOL DEFAULT TRUE);")

    create_device_state = (
        "CREATE TABLE device_state ( "
        "    id INT AUTO_INCREMENT KEY, "
        "    fileHash CHAR(64), "
        "    mac_addr VARCHAR(17), "
        "    internalName VARCHAR(20) DEFAULT NULL, "
        "    fw_ver TEXT DEFAULT NULL, "
        "    ipv4_addr VARCHAR(15), "
        "    ipv6_addr TEXT);")

    create_packet = (
        "CREATE TABLE packet ( "
        "    id INT AUTO_INCREMENT KEY, "
        "    fileHash CHAR(64), "
        "    pkt_datetime DATETIME, "
        "    pkt_epochtime DOUBLE, "
        "    mac_addr VARCHAR(17), "
        "    protocol TEXT, "
        "    ip_ver INT DEFAULT -1, "
        "    ip_src TEXT, "
        "    ip_dst TEXT, "
        "    ew BOOL, "
        "    tlp TEXT, "
        "    tlp_srcport INT DEFAULT -1, "
        "    tlp_dstport INT DEFAULT -1, "
        "    length INT DEFAULT);")

    create_protocol = (
        "CREATE TABLE protocol ( "
        "    id INT AUTO_INCREMENT KEY, "
        "    fileHash CHAR(64), "
        "    mac_addr VARCHAR(17), "
        "    protocol TEXT, "
        "    src_port INT, "
        "    dst_ip_addr TEXT, "
        "    ipv6 BOOL DEFAULT FALSE, "
        "    dst_url TEXT, "
        "    dst_port INT, "
        "    notes TEXT);")

    add_capture = (
        "INSERT INTO capture "
        # TEXT      TEXT     BINARY(32)   DATETIME TEXT      TEXT
        "(fileName, fileLoc, fileHash, capDate, activity, details) "
        #"VALUES (%s, %s, %s, %s, %s, %s);")
        "VALUES (%(fileName)s, %(fileLoc)s, %(fileHash)s, %(capDate)s, %(activity)s, %(details)s);")

    add_device_in_capture = (
        "INSERT INTO device_in_capture "
        # TEXT      VARCHAR   VARCHAR
        "(fileName, fileHash, mac_addr) "
        "VALUES (%(fileName)s, %(fileHash)s, %(mac_addr)s);")
        # TEXT      VARCHAR   VARCHAR    BOOL
        #"(fileName, fileHash, mac_addr, imported) "
        #"VALUES (%(fileName)s, %(fileHash)s, %(mac_addr)s, %(imported)s);")

    change_device_in_capture = (
        "UPDATE device_in_capture "
        "SET imported = %(imported)s "
        # TEXT      VARCHAR   VARCHAR
        "WHERE id=%(id)s AND fileName=%(fileName)s AND fileHash=%(fileHash)s AND "
        #"      mac_addr=%(mac_addr)s AND imported=%(imported)s);")
        "      mac_addr=%(mac_addr)s;")

    add_mac_to_mfr = (
        #"INSERT INTO mac_to_mfr "
        "REPLACE INTO mac_to_mfr "
        # VARCHAR     TEXT
        "(mac_prefix, mfr) "
        "VALUES (%(mac_prefix)s, %(mfr)s);")
    
    add_device = (
        #"INSERT INTO device "
        "REPLACE INTO device "
        # TEXT TEXT   VARCHAR       VARCHAR   TEXT            BOOL       BOOL BOOL BOOL BOOL BOOL       BOOL    BOOL   TEXT            TEXT   BOOL
        "(mfr, model, internalName, mac_addr, deviceCategory, mudCapable, wifi, 3G, 4G, 5G,  bluetooth, zigbee, zwave, otherProtocols, notes, unidentified) "
        "VALUES (%(mfr)s, %(model)s, %(internalName)s, %(mac_addr)s, %(deviceCategory)s, %(mudCapable)s, %(wifi)s, "
        "%(ethernet)s, %(G3)s, %(G4)s, %(G5)s, %(bluetooth)s, %(zigbee)s, %(zwave)s, %(otherProtocols)s, %(notes)s, %(unidentified)s)")

    add_device_unidentified = (
        "INSERT INTO device "
        #"REPLACE INTO device "
        # TEXT VARCHAR   Bool
        "(mac_addr) "
        "VALUES (%(mac_addr)s)")
        #"(mfr, mac_addr) "
        #"VALUES (%(mfr)s, %(mac_addr)s)")

    add_device_state = (
        "INSERT INTO device_state "
        # BINARY       VARCHAR   VARCHAR       TEXT    VARCHAR    TEXT
        "(fileHash, mac_addr, internalName, fw_ver, ipv4_addr, ipv6_addr) "
        "VALUES (%(fileHash)s, %(mac_addr)s, %(internalName)s, %(fw_ver)s, %(ipv4_addr)s, %(ipv6_addr)s);")

    add_device_state_unidentified = (
        "INSERT INTO device_state "
        # BINARY    VARCHAR   VARCHAR    TEXT
        "(fileHash, mac_addr, ipv4_addr, ipv6_addr) "
        "VALUES (%(fileHash)s, %(mac_addr)s, %(ipv4_addr)s, %(ipv6_addr)s);")

    change_device_state = (
        "UPDATE device_state "
        "SET fw_ver = %(fw_ver)s "
        "WHERE id=%(id)s AND fileHash=%(fileHash)s AND mac_addr=%(mac_addr)s;")

    # Temporary Tables of Interest (toi)
    # capture toi
    drop_capture_toi = (
        "DROP TEMPORARY TABLE IF EXISTS cap_toi;")

    create_capture_toi_all = (
        "CREATE TEMPORARY TABLE cap_toi "
        "SELECT DISTINCT(fileHash) "
        "FROM capture;")

    create_capture_toi = (
        "CREATE TEMPORARY TABLE cap_toi "
        "SELECT DISTINCT(fileHash) "
        "FROM capture "
        "WHERE fileName=%(fileName)s;" )

    update_capture_toi = (
        "INSERT INTO cap_toi "
        "SELECT DISTINCT(fileHash) "
        "FROM capture "
        "WHERE fileName=%(fileHash)s;")

    # device toi
    drop_device_toi = (
        "DROP TEMPORARY TABLE IF EXISTS dev_toi;")

    create_device_toi_all = (
        "CREATE TEMPORARY TABLE dev_toi "
        "SELECT d.fileHash, d.mac_addr, d.ipv4_addr, d.ipv6_addr "
        "FROM device_state d "
        "    INNER JOIN cap_toi c ON d.fileHash = c.fileHash;")

    create_device_toi = (
        "CREATE TEMPORARY TABLE dev_toi "
        "SELECT d.fileHash, d.mac_addr, d.ipv4_addr, d.ipv6_addr "
        "FROM device_state d "
        "    INNER JOIN cap_toi c ON d.fileHash = c.fileHash "
        "WHERE d.mac_addr=%(mac_addr)s;")

    update_device_toi = (
        "INSERT INTO dev_toi "
        "SELECT d.fileHash, d.mac_addr, d.ipv4_addr, d.ipv6_addr "
        "FROM device_state d "
        "    INNER JOIN cap_toi c ON d.fileHash = c.fileHash "
        "WHERE d.mac_addr=%(mac_addr)s;")

    # packet toi
    query_packet_toi = (
        "SELECT p.* "
        "FROM packet p "
        "    INNER JOIN dev_toi d "
        "ON (d.fileHash=p.fileHash "
        "    AND (p.mac_addr=d.mac_addr "
        "         OR p.ip_src=(d.ipv4_addr OR d.ipv6_addr) "
        "                OR p.ip_dst=(d.ipv4_addr OR d.ipv6_addr))) "
        "WHERE p.ew=%(ew)s;")

    drop_packet_toi = (
        "DROP TEMPORARY TABLE IF EXISTS pkt_toi;")

    create_packet_toi = (
        "CREATE TEMPORARY TABLE pkt_toi "
        "SELECT * "
        "FROM packet "
        "WHERE fileHash = (SELECT DISTINCT(fileHash) FROM capture WHERE fileName=%(fileName)s);")

    update_packet_toi = (
        "INSERT INTO pkt_toi "
        "SELECT * "
        "FROM packet "
        "WHERE fileHash = (SELECT DISTINCT(fileHash) FROM capture WHERE fileName=%(fileName)s);")

    #;lkj too be completed
    add_pkt = (
        "INSERT INTO packet "
        "    (fileHash, pkt_datetime, pkt_epochtime, mac_addr, "
        "     protocol, ip_ver, ip_src, ip_dst, ew, "
        "     tlp, tlp_srcport, tlp_dstport, length) "
        "SELECT "
        "    %(fileHash)s, FROM_UNIXTIME( %(pkt_timestamp)s ), %(pkt_timestamp)s, %(mac_addr)s, "
        "    %(protocol)s, %(ip_ver)s, %(ip_src)s, %(ip_dst)s, %(ew)s, "
        "    %(tlp)s, %(tlp_srcport)s, %(tlp_dstport)s, %(length)s "
        "WHERE NOT EXISTS (SELECT * FROM packet "
        "                  WHERE fileHash=%(fileHash)s AND pkt_epochtime=%(pkt_timestamp)s);")

    '''
        "INSERT INTO packet "
        "    (fileHash, pkt_datetime, pkt_epochtime, mac_addr, "
        "     protocol, ip_ver, ip_src, ip_dst, ew, "
        "     tlp, tlp_srcport, tlp_dstport, length) "
        "VALUES "
        "    (%(fileHash)s, FROM_UNIXTIME( %(pkt_timestamp)s ), %(pkt_timestamp)s, %(mac_addr)s, "
        "     %(protocol)s, %(ip_ver)s, %(ip_src)s, %(ip_dst)s, %(ew)s, "
        "     %(tlp)s, %(tlp_srcport)s, %(tlp_dstport)s, %(length)s);")
    '''

    add_protocol = ("INSERT INTO protocol "
                    # BINARY       VARCHAR   TEXT      INT       TEXT         BOOL  TEXT     INT       TEXT
                    "(fileHash, mac_addr, protocol, src_port, dst_ip_addr, ipv6, dst_url, dst_port, notes) "
                    #"VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);")
                    "VALUES (%(fileHash)s, %(mac_addr)s, %(protocol), %(src_port)s, %(dst_ip_addr)s, %(ipv6)s, %(dst_url)s, %(dst_port)s, %(notes)s);")

    # Queries
    query_unique_capture = ("SELECT fileHash FROM capture;")

    query_imported_capture = ("SELECT * FROM capture;")

    query_imported_capture_with = (
        "SELECT DISTINCT cap.id, cap.fileName, cap.fileLoc, cap.fileHash, cap.capDate, cap.activity, cap.details "
        "FROM capture as cap "
        "    INNER JOIN ( "
        "      SELECT * FROM device_in_capture "
        "      WHERE mac_addr=%(dev_mac)s) device "
        "        ON device.fileHash = cap.fileHash "
        "    INNER JOIN ( "
        "      SELECT * FROM device_in_capture "
        "      WHERE mac_addr=%(gateway_mac)s) gateway "
        "        ON gateway.fileHash = cap.fileHash;")

    query_imported_capture_with_device = (
        "SELECT DISTINCT cap.id, cap.fileName, cap.fileLoc, cap.fileHash, cap.capDate, cap.activity, cap.details "
        "FROM capture as cap "
        "    INNER JOIN ( "
        "      SELECT * FROM device_in_capture "
        "      WHERE mac_addr=%(dev_mac)s) device "
        "        ON device.fileHash = cap.fileHash;")

    #query_device_from_capture = ("SELECT * FROM device WHERE fileName=%s;")
    #query_device_from_capture = ("SELECT * FROM device_in_capture WHERE fileHash=%s;")
    query_device_from_capture = ("SELECT * FROM device WHERE mac_addr = ANY "
                                 "(SELECT mac_addr FROM device_in_capture WHERE"
                                 #" fileHash=%s);"
                                 " fileName=%s);")

    #query_identified_devices_from_capture = ("SELECT * FROM device_in_capture "
    #                                    "WHERE fileHash = %s AND mac_addr = %s;")
    #query_identified_devices_from_capture = ("SELECT id, mac_addr, imported FROM device_in_capture "
    query_identified_devices_from_capture = ("SELECT * FROM device_in_capture "
                                        "WHERE fileHash = %s;")
                                        #"WHERE fileHash = %s AND imported = TRUE;")

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

    query_mac_to_mfr = ("SELECT * FROM mac_to_mfr;")

    query_devices =  ("SELECT * FROM device;")

    #query_devices_imported = ("SELECT * FROM device WHERE not ISNULL(internalName);")
    query_devices_imported = ("SELECT id, mfr, model, mac_addr, internalName, deviceCategory "
                              "FROM device "
                              "WHERE NOT ISNULL(internalName);")

    query_devices_imported_ignore_noIPs = (
        "SELECT id, mfr, model, mac_addr, internalName, deviceCategory "
        "FROM device "
        #"WHERE internalName!=%(internalName)s AND NOT ISNULL(internalName);")
        "WHERE mac_addr!=%(ignored_dev)s AND NOT ISNULL(internalName);")
    
    query_devices_imported_ignore_known = (
        "SELECT DISTINCT d.id, d.mfr, d.model, d.mac_addr, d.internalName, d.deviceCategory, s.ipv4_addr, s.ipv6_addr "
        "FROM device AS d "
        "    INNER JOIN (SELECT * FROM device_state) AS s ON d.mac_addr=s.mac_addr "
        "WHERE d.mac_addr!=%(ignored_dev)s AND NOT ISNULL(d.internalName);")

    query_devices_imported_ignore = (
        "SELECT DISTINCT d.id, d.mfr, d.model, d.mac_addr, d.internalName, d.deviceCategory, s.ipv4_addr, s.ipv6_addr "
        "FROM device AS d "
        "    INNER JOIN (SELECT * FROM device_state) AS s ON d.mac_addr=s.mac_addr "
        #"WHERE d.mac_addr!=%(ignored_dev)s;")
        #"WHERE d.mac_addr!=%(ignored_dev)s AND s.ipv4_addr!='Not found';")
        "WHERE d.mac_addr!=%(ignored_dev)s AND "
        "s.ipv4_addr!='Not found' AND s.ipv4_addr!='0.0.0.0' AND "
        "s.ipv6_addr!='Not found' AND s.ipv6_addr!='::';")


    query_gateway_ips = (
        "SELECT DISTINCT ipv4_addr, ipv6_addr "
        "FROM device_state "
        #"WHERE mac_addr=%(gateway_mac)s;")
        "WHERE mac_addr=%(gateway_mac)s AND "
        "ipv4_addr!='Not found' AND ipv4_addr!='0.0.0.0' AND "
        "ipv6_addr!='Not found' AND ipv6_addr!='::';")


    query_devices_in_caps_except = (
        "SELECT DISTINCT dc.id, d.internalName, dc.mac_addr "
        "FROM device_in_capture AS dc "
        "    INNER JOIN ( "
        "        SELECT * "
        "        FROM capture "
        "        WHERE id=%(cap_id)s) AS c "
        "    ON dc.fileHash=c.fileHash "
        "    INNER JOIN ( "
        "        SELECT * "
        "        FROM device) AS d "
        "    ON dc.mac_addr = d.mac_addr "
        "WHERE dc.mac_addr != %(mac_addr)s;")

    query_caps_with_device_where = (
        "SELECT DISTINCT "
        "    c.id, c.fileName, c.fileHash, c.activity, c.capDate, c.details "
        "FROM capture AS c "
        "    INNER JOIN ( "
        "        SELECT * "
        "        FROM device_in_capture "
        "        WHERE mac_addr = %(mac_addr)s) AS d "
        "    ON c.fileHash=d.fileHash")

    query_device_info =  ("SELECT * FROM device WHERE mac_addr=%s;")

    query_device_macs = ("SELECT mac_addr FROM device;")

    query_device_state = ("SELECT * FROM device_state WHERE fileHash=%s AND mac_addr=%s;")

    query_device_state_exact = ("SELECT * FROM device_state WHERE "
                                " fileHash=%(fileHash)s AND mac_addr=%(mac_addr)s AND "
                                " internalName=%(internalName)s AND fw_ver=%(fw_ver)s AND "
                                " ipv4_addr=%(ipv4_addr)s AND ipv6_addr=%(ipv6_addr)s;")
    

    query_device_communication = ("SELECT * FROM protocol WHERE device=%s;")

    query_device_communication_by_capture = ("SELECT * FROM protocol WHERE device=%(device)s AND fileHash=%(fileHash)s;")

    query_pkts = ("SELECT * FROM packet;")

    query_pkts_by_capture = ("SELECT * FROM packet WHERE fileHash=%(fileHash)s;")

    #query_pkts_by_capture_and_device = ("SELECT * FROM packet WHERE fileHash=%(fileHash)s AND dev...;")

    #query_pkts_by_device = ("SELECT * FROM packet WEHRE dev...;")

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


    # SQL Initialize New Database
    def init_new_database(self, db_name):
        # Create new database
        self.cursor.execute(self.new_database + db_name + ';')
        self.cnx.commit()

        # Drop the tables if they exist
        self.cursor.execute(self.drop_tables)
        self.cnx.commit()

        # Create all tables
        self.cursor.execute(self.create_capture)
        self.cnx.commit()
        self.cursor.execute(self.create_device_in_capture)
        self.cnx.commit()
        self.cursor.execute(self.create_mac_to_mfr)
        self.cnx.commit()
        self.cursor.execute(self.create_device)
        self.cnx.commit()
        self.cursor.execute(self.create_device_state)
        self.cnx.commit()
        self.cursor.execute(self.create_packet)
        self.cnx.commit()
        self.cursor.execute(self.create_protocol)
        self.cnx.commit()

    def reinit_database(self):
        # Drop the tables if they exist
        self.cursor.execute(self.drop_tables)
        self.cnx.commit()

        # Create all tables
        self.cursor.execute(self.create_capture)
        self.cnx.commit()
        self.cursor.execute(self.create_device_in_capture)
        self.cnx.commit()
        self.cursor.execute(self.create_mac_to_mfr)
        self.cnx.commit()
        self.cursor.execute(self.create_device)
        self.cnx.commit()
        self.cursor.execute(self.create_device_state)
        self.cnx.commit()
        self.cursor.execute(self.create_packet)
        self.cnx.commit()
        self.cursor.execute(self.create_protocol)
        self.cnx.commit()

    # SQL Insertion Commands
    def insert_capture(self, data_capture):
        #self.cap = CaptureDigest(data_capture.get(fpath, "none"))

        self.cursor.execute(self.add_capture, data_capture)
        self.cnx.commit()

    def insert_device(self, data_device):
        self.cursor.execute(self.add_device, data_device)
        self.cnx.commit()

    def insert_device_unidentified(self, data_device):
        self.cursor.execute(self.add_device_unidentified, data_device)
        self.cnx.commit()

    def insert_device_in_capture(self, data_device_in_capture):
        self.cursor.execute(self.add_device_in_capture, data_device_in_capture)
        self.cnx.commit()

    def update_device_in_capture(self, data_device_in_capture):
        self.cursor.execute(self.change_device_in_capture, data_device_in_capture)
        self.cnx.commit()

    def insert_mac_to_mfr(self, data_mac_and_mfr):
        self.cursor.execute(self.add_mac_to_mfr, data_mac_and_mfr)
        self.cnx.commit()

    def insert_device_state(self, data_device_state):
        self.cursor.execute(self.add_device_state, data_device_state)
        self.cnx.commit()

    def insert_device_state_unidentified(self, data_device_state):
        self.cursor.execute(self.add_device_state_unidentified, data_device_state)
        self.cnx.commit()

    def update_device_state(self, data_device_state):
        self.cursor.execute(self.change_device_state, data_device_state)
        self.cnx.commit()

    def insert_packet(self, data_pkt):
        self.cursor.execute(self.add_pkt, data_pkt)
        self.cnx.commit()

    def insert_protocol(self, data_protocol):
        self.cursor.execute(self.add_protocol, data_protocol)
        self.cnx.commit()

    # SQL Query Commands
    def select_unique_captures(self):
        self.cursor.execute(self.query_unique_capture)

    def select_imported_captures(self):
        self.cursor.execute(self.query_imported_capture)

    #def select_imported_captures_with(self, device, gateway):
    #    self.cursor.execute(self.query_imported_capture_with, devices)

    def select_imported_captures_with(self, devices):
        self.cursor.execute(self.query_imported_capture_with, devices)

    def select_imported_captures_with_device(self, device):
        self.cursor.execute(self.query_imported_capture_with_device, device)

    def select_devices_from_cap(self, capture):
        #print(capture)
        self.cursor.execute(self.query_device_from_capture, (capture,))

    def select_identified_devices_from_cap(self, fileHash):
        self.cursor.execute(self.query_identified_devices_from_capture, (fileHash,))

    def select_most_recent_fw_ver(self, macdatemac):
        self.cursor.execute(self.query_most_recent_fw_ver, macdatemac)

    def select_mac_to_mfr(self):
        self.cursor.execute(self.query_mac_to_mfr)

    def select_devices(self):
        self.cursor.execute(self.query_devices)
    
    def select_devices_imported(self):
        self.cursor.execute(self.query_devices_imported)

    def select_devices_imported_ignore(self, ignored_dev):
        self.cursor.execute(self.query_devices_imported_ignore, ignored_dev)

    def select_gateway_ips(self, gateway):
        self.cursor.execute(self.query_gateway_ips, gateway)

    def select_devices_in_caps_except(self, condition_data):
        self.cursor.execute(self.query_devices_in_caps_except, condition_data)

    def select_caps_with_device_where(self, mac_addr_data, conditions):
        self.cursor.execute(self.query_caps_with_device_where + conditions, mac_addr_data)

    def select_device(self, mac):
        self.cursor.execute(self.query_device_info, (mac,))

    def select_device_state(self, hash, mac):
        self.cursor.execute(self.query_device_state, (hash, mac))

    def select_device_state_exact(self, device_state_data):
        self.cursor.execute(self.query_device_state_exact, device_state_data)

    def select_device_macs(self):
        self.cursor.execute(self.query_device_macs)                                                                                

    # work to be done
    def select_packets(self):
        self.cursor.execute(self.query_pkts)

    def select_packets_by_capture(self, pkt_data_capture):
        self.cursor.execute(self.query_pkt_by_capture, pkt_data_capture)

    def select_packets_by_device(self, pkt_data_device):
        self.cursor.execute(self.query_pkt_by_device, pkt_data_device)

    def select_packets_by_capture_and_device(self, pkt_data):
        self.cursor.execute(self.query_pkt_by_capture_and_device, pkt_data)

    '''
    def select_device_communication(self, device):
        self.cursor.execute(self.query_device_communication, device)
    '''

    def select_device_strings(self, device):
        self.cursor.execute(self.query_device_strings, device)

    # Capture table of interest
    def drop_cap_toi(self):
        self.cursor.execute(self.drop_capture_toi)
        self.cnx.commit()

    def create_cap_toi(self, capture=None):
        if capture==None:
            self.cursor.execute(self.create_capture_toi_all)
        else:
            self.cursor.execute(self.create_capture_toi, capture)
        self.cnx.commit()

    def update_cap_toi(self, capture):
        self.cursor.execute(self.update_capture_toi, capture)
        self.cnx.commit()

    # Device table of interest
    def drop_dev_toi(self):
        self.cursor.execute(self.drop_device_toi)
        self.cnx.commit()

    def create_dev_toi(self, mac=None):
        if mac == None:
            self.cursor.execute(self.create_device_toi_all)
        else:
            self.cursor.execute(self.create_device_toi, mac)
        self.cnx.commit()

    def update_dev_toi(self):
        self.cursor.execute(self.update_device_toi, mac)
        self.cnx.commit()

    # Packet table of interest
    def select_pkt_toi(self, ew):
        self.cursor.execute(self.query_packet_toi, ew)

    def drop_pkt_toi(self):
        self.cursor.execute(self.drop_packet_toi)
        self.cnx.commit()

    def create_pkt_toi(self, capture):
        self.cursor.execute(self.create_packet_toi, capture)
        self.cnx.commit()

    def update_pkt_toi(self, capture):
        self.cursor.execute(self.update_packet_toi, capture)
        self.cnx.commit()


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


    def __init__(self, fpath):#, gui=False):
        self.fpath = fpath
        self.fdir, self.fname = os.path.split(fpath)
        self.fsize = os.path.getsize(fpath)
        print("file size: ", self.fsize)
        self.progress = 24 #capture header
        self.fileHash = hashlib.md5(open(fpath,'rb').read()).hexdigest()
        #self.fileHash = hashlib.sha256(open(fpath,'rb').read()).hexdigest()

        ew_ip_filter = 'ip.src in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8} and ip.dst in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8}'
        ns_ip_filter = '!ip.src in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8} or !ip.dst in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8}'
        ew_ipv6_filter = 'ipv6.src in {fd00::/8} and ipv6.dst in {fd00::/8}'
        ns_ipv6_filter = '!ipv6.src in {fd00::/8} or !ipv6.dst in {fd00::/8}'

        # (ip.src in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8} and ip.dst in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8}) or (ipv6.src in {fd00::/8} and ipv6.dst in {fd00::/8})
        #ew_filter = ['(', ew_ip_filter, ') or (', ew_ipv6_filter, ')']
        ew_filter = '(ip.src in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8} and ip.dst in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8}) or (ipv6.src in {fd00::/8} and ipv6.dst in {fd00::/8})'
        # (!ip.src in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8} or !ip.dst in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8}) and (!ipv6.src in {fd00::/8} or !ipv6.dst in {fd00::/8})
        ns_filter = ['(', ns_ip_filter, ') and (', ns_ipv6_filter, ')']

        #start = datetime.now()
        self.cap = pyshark.FileCapture(fpath)

        self.ew_index = []
        self.cap_ew = pyshark.FileCapture(fpath, display_filter=ew_filter)
        for p in self.cap_ew:
            self.ew_index += p.number
        #stop = datetime.now()
        #print("time to open capture with pyshark = %f seconds" % (stop-start).total_seconds())

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

        # str(first[len(first.__dict__['layers'])-1]).split()[1].strip(":")
        self.protocol = []

        self.num_pkts = 0
        self.pkt = [] 

        self.pkt_info = [] #needs to be a list of dictionary

        #Fastest way to get the number of packets in capture, but still slow to do
        '''
        start = datetime.now()
        self.cap.apply_on_packets(self.count)
        stop = datetime.now()
        print("time to get pkt count = %f seconds" % (stop-start).total_seconds())
        print("count = ", self.num_pkts)
        '''
        
        #trying to use subprocess
        #self.num_pkts = subprocess.check_output(["tcpdump -r " + fpath])





        '''
        start = datetime.now()
        #self.cap.apply_on_packets(self.import_pkts)
        self.cap.apply_on_packets(self.append_pkt)
        stop = datetime.now()
        print("time to import_packets = %f seconds" % (stop-start).total_seconds())
        '''

        #start = datetime.now()
        #self.import_pkts()
        #stop = datetime.now()
        #print("time to import_packets = %f seconds" % (stop-start).total_seconds())





        #print("cap length = ", len(self.pkt))

        '''
        start = datetime.now()
        self.cap.apply_on_packets(self.id_unique_addrs)
        stop = datetime.now()
        print("time to process_packets from object: %f seconds" % (stop-start).total_seconds())

        '''
        
        #Much faster than running "self.cap.apply_on_packets(self.id_unique_addrs)", but requires slower up front processing
        #start = datetime.now()






        '''
        for i, p in enumerate(self.pkt):
            if i < 2:
                print(p)
            self.id_unique_addrs(p)
        '''





        #stop = datetime.now()
        #print("time to process_packets from list: %f seconds" % (stop-start).total_seconds())

        #self.id_unique_addrs()

    '''
    def count(self, *args):
        self.num_pkts += 1;
    '''

    def import_pkts(self):
        print("in import_pkts")
        self.cap.apply_on_packets(self.append_pkt)


        #:LKJ
        self.extract_pkts()
        self.id_unique_addrs()
        '''
        for i, p in enumerate(self.pkt):
            #if i < 2:
            #    print(p)
            #self.id_unique_addrs(p)
            self.id_addr(p)
        '''

#    def import_pkts(self, *args):
    def append_pkt(self, *args):
        #print("length = ", args[0].length)
        self.progress += int(args[0].length) + 16 #packet header
        #print(self.progress, "/", self.fsize)
        self.pkt.append(args[0])
        #exit()
        
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

    def findIPs(self, mac):
        if (mac, "ipv4") in self.ip2mac:
            ip = self.ip2mac[(mac, "ipv4")]
        else:
            ip = "Not found"

        if (mac, "ipv6") in self.ip2mac:
            ipv6 = self.ip2mac[(mac, "ipv6")]
        else:
            ipv6 = "Not found"

        return (ip, ipv6)

    def extract_pkts(self):
        for p in self.pkt:
            self.pkt_info.append({"pkt_timestamp":p.sniff_timestamp,
                                  "mac_addr":'',
                                  "protocol":p.layers[-1].layer_name.upper(),
                                  "ip_ver":'-1',
                                  "ip_src":'',
                                  "ip_dst":'',
                                  "ew": p.number in self.ew_index,
                                  "tlp":'',
                                  "tlp_srcport":'-1',
                                  "tlp_dstport":'-1',
                                  "length":p.length})
                                  #"raw":p})

            '''
            self.pkt_info[-1]{"time":p.sniff_timestamp,
                              "length":p.length,
                              "protocol":p.layers[-1].layer_name.upper(),
                              "raw":p}
            '''
            for l in p.layers:
                if l.layer_name == "sll":
                    self.pkt_info[-1]["mac_addr"] = l.src_eth
                    #self.pkt_info[-1]["mac"] = l._all_fields["sll.src.eth"]
                elif l.layer_name == "eth":
                    self.pkt_info[-1]["mac_addr"] = l.addr
                elif l.layer_name == "ip":
                    #self.pkt_info[-1]["ip_ver"] = l.ip.version
                    #self.pkt_info[-1]["ip_src"] = l.ip.src
                    #self.pkt_info[-1]["ip_dst"] = l.ip.dst
                    self.pkt_info[-1]["ip_ver"] = l.version
                    self.pkt_info[-1]["ip_src"] = l.src
                    self.pkt_info[-1]["ip_dst"] = l.dst
                    #self.pkt_info[-1]["ip_ver"] = l._all_fields["ip.version"]
                    #self.pkt_info[-1]["ip_src"] = l._all_fields["ip.src"]
                    #self.pkt_info[-1]["ip_dst"] = l._all_fields["ip.dst"]
                elif l.layer_name == "ipv6":
                    self.pkt_info[-1]["ip_ver"] = l.version
                    self.pkt_info[-1]["ip_src"] = l.src
                    self.pkt_info[-1]["ip_dst"] = l.dst
                elif l.layer_name == "tcp":
                    self.pkt_info[-1]["tlp"] = "tcp"
                    #self.pkt_info[-1]["tlp_srcport"] = l.tcp.srcport
                    #self.pkt_info[-1]["tlp_dstport"] = l.tcp.dstport
                    self.pkt_info[-1]["tlp_srcport"] = l.srcport
                    self.pkt_info[-1]["tlp_dstport"] = l.dstport
                    #self.pkt_info[-1]["tcp_srcport"] = l.tcp.srcport
                    #self.pkt_info[-1]["tcp_dstport"] = l.tcp.dstport
                    ##self.pkt_info[-1]["tcp_srcport"] = l._all_fields["tcp.srcport"]
                    ##self.pkt_info[-1]["tcp_dstport"] = l._all_fields["tcp.dstport"]
                    #self.pkt_info[-1]["udp_srcport"] = ''
                    #self.pkt_info[-1]["udp_dstport"] = ''
                elif l.layer_name == "udp":
                    self.pkt_info[-1]["tlp"] = "udp"
                    #self.pkt_info[-1]["tlp_srcport"] = l.udp.srcport
                    #self.pkt_info[-1]["tlp_dstport"] = l.udp.dstport
                    self.pkt_info[-1]["tlp_srcport"] = l.srcport
                    self.pkt_info[-1]["tlp_dstport"] = l.dstport
                    #self.pkt_info[-1]["udp_srcport"] = l.udp.srcport
                    #self.pkt_info[-1]["udp_dstport"] = l.udp.dstport
                    ##self.pkt_info[-1]["udp_srcport"] = l._all_fields["udp.srcport"]
                    ##self.pkt_info[-1]["udp_dstport"] = l._all_fields["udp.dstport"]
                    #self.pkt_info[-1]["tcp_srcport"] = ''
                    #self.pkt_info[-1]["tcp_dstport"] = ''
                elif l.layer_name != p.layers[-1].layer_name:
                    print("Warning: Unknown/Unsupported layer seen here:", l.layer_name)
                #could add some sort of check for the direction here, potentially. Maybe add post
                #self.pkt_info[-1]["direction"] = #n/s or e/w


    def id_unique_addrs(self):
        for p in self.pkt:
            self.id_addr(p) #;lkj
            
            #:LKJ
            '''
            self.pkt_info[-1]["time"] = sniff_timestamp
            #self.pkt_info[-1]["dst"] = p.ip.dst?
            self.pkt_info[-1]["protocol"] = p.layers[-1].layer_name.upper()
            self.pkt_info[-1]["length"] = p.length
            #self.pkt_info[-1]["direction"] = #n/s or e/w
            self.pkt_info[-1]["raw"] = p
            '''

    def id_addr(self, pkt):
        # Try to get the MAC address
        try:
            pMAC = pkt.eth.src
        except:
            pMAC = pkt.sll.src_eth

        #;lkj
        #self.pkt_info.append({})
        #self.pkt_info[-1]["mac"] = pMAC

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

                #self.pkt_info[-1]["src_ip"] = pIPv6
                #self.pkt_info[-1]["ver"] = "v6"
        else:
            if (pMAC, "ipv4") not in self.ip2mac:
                self.ip2mac[(pMAC, "ipv4")] = pIP
            # Add unique IPs to the list
            if pIP not in self.uniqueIP:
                #print(pIP)
                self.uniqueIP.append(pIP)

            #self.pkt_info[-1]["src_ip"] = pIP
            #self.pkt_info[-1]["ver"] = "v4"


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

    #TBD in the future (2019-06-13)
    def load_from_db(self, fpath):
        self.fpath = fpath
        self.fdir, self.fname = os.path.split(fpath)
        self.fileHash = hashlib.md5(open(fpath,'rb').read()).hexdigest()
        #self.fileHash = hashlib.sha256(open(fpath,'rb').read()).hexdigest()

        self.cap = pyshark.FileCapture(fpath)

        self.capTimeStamp = self.cap[0].sniff_timestamp
        (self.capDate, self.capTime) = datetime.utcfromtimestamp(float(self.capTimeStamp)).strftime('%Y-%m-%d %H:%M:%S').split()

        print(self.capDate)
        print(self.capTime)

        self.uniqueIP = []
        self.uniqueIPv6 = []
        self.uniqueMAC = []

        self.ip2mac = {}

        self.uniqueIP_dst = []
        self.uniqueIPv6_dst = []

        self.protocol = []

        self.num_pkts = 0
        self.pkt = [] 

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
