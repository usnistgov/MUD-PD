#! /usr/bin/python3

import hashlib

# MySQl libraries
from configparser import ConfigParser
from datetime import datetime
from datetime import timedelta
# from lookup import *
from src.lookup import *
from multiprocessing import Pool
import mysql.connector
from mysql.connector import MySQLConnection, Error
import os
import pyshark
import subprocess


class CaptureDatabase:
    new_database = (
        "CREATE DATABASE ")

    use_database = (
        "USE ")

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
        "    lifecyclePhase VARCHAR(16), "
        "    internet BOOL DEFAULT TRUE, "
        "    humanInteraction BOOL DEFAULT TRUE, "
        "    preferredDNS BOOL DEFAULT TRUE, "
        "    isolated BOOL DEFAULT TRUE, "
        "    durationBased BOOL DEFAULT FALSE, "
        "    duration TEXT DEFAULT NULL, "
        "    actionBased BOOL DEFAULT TRUE, "
        "    deviceAction TEXT DEFAULT NULL, "
        "    details TEXT DEFAULT NULL);")

    create_device_in_capture = (
        "CREATE TABLE device_in_capture ( "
        "    id INT PRIMARY KEY AUTO_INCREMENT, "
        # "    fileName TEXT, "
        # "    fileHash CHAR(64), "
        "    fileID INT, "
        # "    mac_addr VARCHAR(17));")
        "    deviceID INT);")

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
        # "    unidentified BOOL DEFAULT TRUE);")
        "    unlabeled BOOL DEFAULT TRUE);")

    create_device_state = (
        "CREATE TABLE device_state ( "
        "    id INT AUTO_INCREMENT KEY, "
        # "    fileHash CHAR(64), "
        "    fileID INT, "
        # "    fileHash CHAR(64), "
        "    deviceID INT, "
        # "    internalName VARCHAR(20) DEFAULT NULL, "
        "    fw_ver TEXT DEFAULT NULL, "
        "    ipv4_addr VARCHAR(15), "
        # "    ipv6_addr TEXT);")
        "    ipv6_addr VARCHAR(39));")

    create_packet = (
        "CREATE TABLE packet ( "
        "    id INT AUTO_INCREMENT KEY, "
        # "    fileHash CHAR(64), "
        "    fileID INT, "
        "    pkt_datetime DATETIME, "
        "    pkt_epochtime DOUBLE, "
        "    mac_addr VARCHAR(17), "
        "    protocol TEXT, "
        "    ip_ver INT DEFAULT NULL, "  # changed -1 to NULL
        # "    ip_src TEXT, "
        # "    ip_dst TEXT, "
        "    ip_src VARCHAR(39) DEFAULT NULL, "
        "    ip_dst VARCHAR(39) DEFAULT NULL, "
        "    ew BOOL, "
        # "    tlp TEXT, "
        "    tlp CHAR(3) DEFAULT NULL, "
        "    tlp_srcport INT DEFAULT NULL, "
        "    tlp_dstport INT DEFAULT NULL, "
        # "    length INT DEFAULT -1);")
        "    length INT DEFAULT NULL);")

    create_protocol = (
        "CREATE TABLE protocol ( "
        "    id INT AUTO_INCREMENT KEY, "
        # "    fileHash CHAR(64), "
        "    fileID INT, "
        # "    mac_addr VARCHAR(17), "
        "    deviceID INT, "
        "    protocol TEXT, "
        "    src_port INT, "
        "    dst_ip_addr TEXT, "
        "    ipv6 BOOL DEFAULT FALSE, "
        "    dst_url TEXT, "
        "    dst_port INT, "
        "    notes TEXT);")

    '''
    add_capture = (
        "INSERT INTO capture "
        # TEXT      TEXT     BINARY(32)  DATETIME  TEXT      TEXT
        #"(fileName, fileLoc, fileHash,   capDate, activity, details) "
        # TEXT      TEXT     BINARY(32)  DATETIME TEXT      INT       TEXT
        "(fileName, fileLoc, fileHash,   capDate, capDuration, activity, details) "
        #"VALUES (%s, %s, %s, %s, %s, %s);")
        #"VALUES (%(fileName)s, %(fileLoc)s, %(fileHash)s, %(capDate)s, %(activity)s, %(details)s);")
        "VALUES (%(fileName)s, %(fileLoc)s, %(fileHash)s, %(capDate)s, %(capDuration)s, %(activity)s, %(details)s);")
    '''
    add_capture = (

        "INSERT INTO capture "
        # TEXT      TEXT     VARCHAR(64)  DATETIME  TEXT       VARCHAR(16)     BOOL
        "(fileName, fileLoc, fileHash,   capDate, capDuration, lifecyclePhase, internet, "
        # BOOL             BOOL          BOOL      BOOL           TEXT      BOOL         TEXT          TEXT
        "humanInteraction, preferredDNS, isolated, durationBased, duration, actionBased, deviceAction, details) "

        "VALUES (%(fileName)s, %(fileLoc)s, %(fileHash)s, %(capDate)s, %(capDuration)s, %(lifecyclePhase)s, %(internet)s, "
        "%(humanInteraction)s, %(preferredDNS)s, %(isolated)s, %(durationBased)s, %(duration)s, %(actionBased)s, %(deviceAction)s, %(details)s);")

    add_device_in_capture = (
        "INSERT INTO device_in_capture "
        ## TEXT      VARCHAR   VARCHAR
        # "(fileName, fileHash, mac_addr) "
        # "VALUES (%(fileName)s, %(fileHash)s, %(mac_addr)s);")
        # INT     INT
        # "(fileID, mac_addr) "
        "(fileID, deviceID) "
        "VALUES (%(fileID)s, %(deviceID)s);")
    # TEXT      VARCHAR   VARCHAR    BOOL
    # "(fileName, fileHash, mac_addr, imported) "
    # "VALUES (%(fileName)s, %(fileHash)s, %(mac_addr)s, %(imported)s);")

    add_device_in_capture_unique = (
        "INSERT INTO device_in_capture "
        "    (fileID, deviceID)"
        "SELECT %(fileID)s, %(deviceID)s "
        "WHERE NOT EXISTS (SELECT fileID, deviceID "
        "                  FROM device_in_capture "
        "                  WHERE fileID=%(fileID)s AND deviceID=%(deviceID)s)")

    change_device_in_capture = (
        "UPDATE device_in_capture "
        "SET imported = %(imported)s "
        ## TEXT      VARCHAR   VARCHAR
        # "WHERE id=%(id)s AND fileName=%(fileName)s AND fileHash=%(fileHash)s AND "
        ##"      mac_addr=%(mac_addr)s AND imported=%(imported)s);")
        # "      mac_addr=%(mac_addr)s;")
        # TEXT      VARCHAR   VARCHAR
        "WHERE id=%(id)s;")

    add_mac_to_mfr = (
        # "INSERT INTO mac_to_mfr "
        # "REPLACE INTO mac_to_mfr "
        "INSERT INTO mac_to_mfr "
        # VARCHAR     TEXT
        "(mac_prefix, mfr) "
        "VALUES (%(mac_prefix)s, %(mfr)s) "
        "ON DUPLICATE KEY UPDATE id=last_insert_id(id), mfr=%(mfr)s;")

    add_device = (
        # "INSERT INTO device "
        # "REPLACE INTO device "
        "INSERT INTO device "
        # TEXT TEXT   VARCHAR       VARCHAR   TEXT            BOOL       BOOL   BOOL    BOOL BOOL BOOL BOOL       BOOL    BOOL   TEXT            TEXT   BOOL
        # "(mfr, model, internalName, mac_addr, deviceCategory, mudCapable, wifi, ethernet, 3G, 4G, 5G,  bluetooth, zigbee, zwave, otherProtocols, notes, unidentified) "
        "(mfr, model, internalName, mac_addr, deviceCategory, mudCapable, wifi, ethernet, 3G, 4G, 5G,  bluetooth, zigbee, zwave, otherProtocols, notes, unlabeled) "
        "VALUES (%(mfr)s, %(model)s, %(internalName)s, %(mac_addr)s, %(deviceCategory)s, %(mudCapable)s, %(wifi)s, "
        # "%(ethernet)s, %(G3)s, %(G4)s, %(G5)s, %(bluetooth)s, %(zigbee)s, %(zwave)s, %(otherProtocols)s, %(notes)s, %(unidentified)s)")
        "%(ethernet)s, %(G3)s, %(G4)s, %(G5)s, %(bluetooth)s, %(zigbee)s, %(zwave)s, %(otherProtocols)s, %(notes)s, %(unlabeled)s) "
        "ON DUPLICATE KEY UPDATE id=last_insert_id(id), mfr=%(mfr)s, model=%(model)s, internalName=%(internalName)s, deviceCategory=%(deviceCategory)s, "
        "mudCapable=%(mudCapable)s, wifi=%(wifi)s, ethernet=%(ethernet)s, 3G=%(G3)s, 4G=%(G4)s, 5G=%(G5)s, bluetooth=%(bluetooth)s, "
        "zigbee=%(zigbee)s, zwave=%(zwave)s, otherProtocols=%(otherProtocols)s, notes=%(notes)s, unlabeled=%(unlabeled)s;")

    # add_device_unidentified = (
    add_device_unlabeled = (
        "INSERT INTO device "
        # "REPLACE INTO device "
        # TEXT VARCHAR   Bool
        # "(mac_addr) "
        # "VALUES (%(mac_addr)s)")
        "(mfr, mac_addr) "
        "VALUES (%(mfr)s, %(mac_addr)s) "
        "ON DUPLICATE KEY UPDATE id=last_insert_id(id), mfr=%(mfr)s;")
    # "(mfr, mac_addr) "
    # "VALUES (%(mfr)s, %(mac_addr)s)")

    # add_device_state = (
    #    "INSERT INTO device_state "
    #    ## BINARY       VARCHAR   VARCHAR       TEXT    VARCHAR    TEXT
    #    #"(fileHash, mac_addr, internalName, fw_ver, ipv4_addr, ipv6_addr) "
    #    #"VALUES (%(fileHash)s, %(mac_addr)s, %(internalName)s, %(fw_ver)s, %(ipv4_addr)s, %(ipv6_addr)s);")
    #    # INT     INT       TEXT    VARCHAR    TEXT
    #    "(fileID, deviceID, fw_ver, ipv4_addr, ipv6_addr) "
    #    "VALUES (%(fileID)s, %(deviceID)s, %(fw_ver)s, %(ipv4_addr)s, %(ipv6_addr)s);")

    add_device_state = (
        "INSERT INTO device_state "
        ## BINARY       VARCHAR   VARCHAR       TEXT    VARCHAR    TEXT
        # "(fileHash, mac_addr, internalName, fw_ver, ipv4_addr, ipv6_addr) "
        # "VALUES (%(fileHash)s, %(mac_addr)s, %(internalName)s, %(fw_ver)s, %(ipv4_addr)s, %(ipv6_addr)s);")
        # INT     INT       TEXT    VARCHAR    TEXT
        "(fileID, deviceID, fw_ver, ipv4_addr, ipv6_addr) "
        "SELECT %(fileID)s, %(deviceID)s, %(fw_ver)s, %(ipv4_addr)s, %(ipv6_addr)s "
        "WHERE NOT EXISTS ( "
        "    SELECT fileID, deviceID, fw_ver, ipv4_addr, ipv6_addr "
        "    FROM device_state "
        "    WHERE fileID    = %(fileID)s AND "
        "          deviceID  = %(deviceID)s AND "
        "          fw_ver    = %(fw_ver)s AND "
        "          ipv4_addr = %(ipv4_addr)s AND "
        "          ipv6_addr = %(ipv6_addr)s);")

    # add_device_state_unidentified = (
    # add_device_state_unlabeled = (
    #    "INSERT INTO device_state "
    #    ## BINARY    VARCHAR   VARCHAR    TEXT
    #    #"(fileHash, mac_addr, ipv4_addr, ipv6_addr) "
    #    #"VALUES (%(fileHash)s, %(mac_addr)s, %(ipv4_addr)s, %(ipv6_addr)s);")
    #    # INT     INT       VARCHAR    TEXT
    #    "(fileID, deviceID, ipv4_addr, ipv6_addr) "
    #    "VALUES (%(fileID)s, %(deviceID)s, %(ipv4_addr)s, %(ipv6_addr)s);")

    add_device_state_unlabeled = (
        "INSERT INTO device_state "
        ## BINARY    VARCHAR   VARCHAR    TEXT
        # "(fileHash, mac_addr, ipv4_addr, ipv6_addr) "
        # "VALUES (%(fileHash)s, %(mac_addr)s, %(ipv4_addr)s, %(ipv6_addr)s);")
        # INT     INT       VARCHAR    TEXT
        "(fileID, deviceID, ipv4_addr, ipv6_addr) "
        "SELECT %(fileID)s, %(deviceID)s, %(ipv4_addr)s, %(ipv6_addr)s "
        "WHERE NOT EXISTS ( "
        "    SELECT fileID, deviceID, ipv4_addr, ipv6_addr "
        "    FROM device_state "
        "    WHERE fileID    = %(fileID)s AND "
        "          deviceID  = %(deviceID)s AND "
        "          ipv4_addr = %(ipv4_addr)s AND "
        "          ipv6_addr = %(ipv6_addr)s);")

    change_device_state = (
        "UPDATE device_state "
        "SET fw_ver = %(fw_ver)s "
        # "WHERE id=%(id)s AND fileHash=%(fileHash)s AND mac_addr=%(mac_addr)s;")
        "WHERE id=%(id)s;")

    # Temporary Tables of Interest (toi)
    # capture toi
    drop_capture_toi = (
        "DROP TEMPORARY TABLE IF EXISTS cap_toi;")

    create_capture_toi_all = (
        "CREATE TEMPORARY TABLE cap_toi "
        # "SELECT DISTINCT(fileHash) "
        "SELECT DISTINCT(id) "
        "FROM capture;")

    '''
    create_capture_toi = (
        "CREATE TEMPORARY TABLE cap_toi "
        #"SELECT DISTINCT(fileHash) "
        "SELECT DISTINCT(id) "
        "FROM capture "
        "WHERE fileName=%(fileName)s;" )
    '''
    create_capture_toi = (
        "CREATE TEMPORARY TABLE cap_toi "
        "SELECT DISTINCT(id) "
        "FROM capture "
        "WHERE fileID=%(cap_id)s;")

    '''
    update_capture_toi = (
        "INSERT INTO cap_toi "
        #"SELECT DISTINCT(fileHash) "
        "SELECT DISTINCT(id) "
        "FROM capture "
        #"WHERE fileName=%(fileHash)s;")
        "WHERE fileName=%(fileName)s;")
    '''
    update_capture_toi = (
        "INSERT INTO cap_toi "
        "SELECT DISTINCT(id) "
        "FROM capture "
        "WHERE fileID=%(cap_id)s;")

    # device toi
    drop_device_toi = (
        "DROP TEMPORARY TABLE IF EXISTS dev_toi;")

    create_device_toi_all = (
        "CREATE TEMPORARY TABLE dev_toi "
        # "SELECT d.fileHash, d.mac_addr, d.ipv4_addr, d.ipv6_addr "
        "SELECT d.fileID, d.deviceID, d.ipv4_addr, d.ipv6_addr "
        "FROM device_state d "
        # "    INNER JOIN cap_toi c ON d.fileHash = c.fileHash;")
        "    INNER JOIN cap_toi c ON d.fileID = c.id;")

    create_device_toi = (
        "CREATE TEMPORARY TABLE dev_toi "
        # "SELECT d.fileHash, d.mac_addr, d.ipv4_addr, d.ipv6_addr "
        "SELECT d.fileID, d.deviceID, d.ipv4_addr, d.ipv6_addr "
        "FROM device_state d "
        # "    INNER JOIN cap_toi c ON d.fileHash = c.fileHash "
        # "WHERE d.mac_addr=%(mac_addr)s;")
        "    INNER JOIN cap_toi c ON d.fileID = c.id "
        "WHERE d.deviceID=%(deviceID)s;")

    # create_device_toi_from_deviceID_list = (
    create_device_toi_from_captureID_list = (
        # "DROP TEMPORARY TABLE IF EXISTS dev_toi;"
        "CREATE TEMPORARY TABLE dev_toi "
        "SELECT ds.fileID, ds.deviceID, d.mac_addr, ds.ipv4_addr, ds.ipv6_addr "
        "FROM device_state ds "
        "    INNER JOIN device d ON d.id=ds.deviceID "
        "WHERE ds.fileID IN (%s);")

    update_device_toi = (
        "INSERT INTO dev_toi "
        # "SELECT d.fileHash, d.mac_addr, d.ipv4_addr, d.ipv6_addr "
        "SELECT d.fileID, d.deviceID, d.ipv4_addr, d.ipv6_addr "
        "FROM device_state d "
        # "    INNER JOIN cap_toi c ON d.fileHash = c.fileHash "
        # "WHERE d.mac_addr=%(mac_addr)s;")
        "    INNER JOIN cap_toi c ON d.fileID = c.id "
        "WHERE d.deviceID=%(deviceID)s;")

    # packet toi
    '''
    query_packet_toi = (
        "SELECT p.* "
        "FROM packet p "
        "    INNER JOIN dev_toi d "
        #"ON (d.fileHash=p.fileHash "
        #"    AND (p.mac_addr=d.mac_addr "
        "ON (d.fileID = p.fileID "
        "    AND (p.mac_addr=d.mac_addr "
        #"    AND (p.deviceID = d.id "
        "         OR p.ip_src=(d.ipv4_addr OR d.ipv6_addr) "
        "                OR p.ip_dst=(d.ipv4_addr OR d.ipv6_addr))) "
        "WHERE p.ew=%(ew)s;")
    '''

    '''
        query_packet_toi = (
        "SELECT p.* "
        "FROM pkt_toi p "
        "    INNER JOIN dev_toi d "
        #"ON (d.fileHash=p.fileHash "
        #"    AND (p.mac_addr=d.mac_addr "
        "ON (d.fileID = p.fileID "
        "    AND (p.mac_addr=d.mac_addr "
        #"    AND (p.deviceID = d.id "
        "         OR p.ip_src=(d.ipv4_addr OR d.ipv6_addr) "
        "                OR p.ip_dst=(d.ipv4_addr OR d.ipv6_addr))) "
        #"WHERE p.ew=%(ew)s LIMIT %(num_pkts)s;")
        "WHERE d.deviceID IN (%(deviceIDs)s) AND p.ew=%(ew)s LIMIT %(num_pkts)s;")
        #"WHERE deviceID IN (%s) AND p.ew=%s LIMIT %s;")

    '''
    '''
    query_packet_toi = (
        "SELECT p.* \n"
        "FROM pkt_toi p \n"
        "    INNER JOIN dev_toi d \n"
        "    ON (p.mac_addr=d.mac_addr OR \n"
        "        p.ip_src=(d.ipv4_addr OR d.ipv6_addr) OR \n"
        "        p.ip_dst=(d.ipv4_addr OR d.ipv6_addr)) \n"
        #"WHERE d.deviceID IN (%(deviceIDs)s) AND p.ew=%(ew)s LIMIT %(num_pkts)s;")
        #"WHERE p.ew IN (%(ew)s) LIMIT %(num_pkts)s;")
        "WHERE d.deviceID IN (%(deviceIDs)s) \nAND p.ew IN (%(ew)s) LIMIT %(num_pkts)s;")
    '''
    query_packet_toi = (
        "SELECT p.* \n"
        "FROM pkt_toi p \n"
        "    INNER JOIN (\n"
        "        SELECT * FROM dev_toi \n"
        "        WHERE deviceID IN (%(deviceIDs)s)) AS d \n"
        "    ON (p.mac_addr = d.mac_addr OR \n"
        "        p.ip_src   = d.ipv4_addr OR \n"
        "        p.ip_src   = d.ipv6_addr OR \n"
        "        p.ip_dst   = d.ipv4_addr OR \n"
        "        p.ip_dst   = d.ipv6_addr) \n"
        "WHERE p.ew IN (%(ew)s) LIMIT %(num_pkts)s;")

    drop_packet_toi = (
        "DROP TEMPORARY TABLE IF EXISTS pkt_toi;")
    '''
    create_packet_toi = (
        "CREATE TEMPORARY TABLE pkt_toi "
        "SELECT * "
        "FROM packet "
        #"WHERE fileHash = (SELECT DISTINCT(fileHash) FROM capture WHERE fileName=%(fileName)s);")
        "WHERE fileID = (SELECT DISTINCT(id) FROM capture WHERE fileName=%(fileName)s);")
    '''
    create_packet_toi = (
        "CREATE TEMPORARY TABLE pkt_toi "
        "SELECT * "
        "FROM packet "
        "WHERE fileID = %(cap_id)s;")

    create_packet_toi_from_captureID_list = (
        "CREATE TEMPORARY TABLE pkt_toi "
        "SELECT * "
        "FROM packet "
        "WHERE fileID IN (%s);")

    '''
    update_packet_toi = (
        "INSERT INTO pkt_toi "
        "SELECT * "
        "FROM packet "
        #"WHERE fileHash = (SELECT DISTINCT(fileHash) FROM capture WHERE fileName=%(fileName)s);")
        "WHERE fileID = (SELECT DISTINCT(id) FROM capture WHERE fileName=%(fileName)s);")
    '''
    update_packet_toi = (
        "INSERT INTO pkt_toi "
        "SELECT * "
        "FROM packet "
        "WHERE fileID = %(cap_id)s;")

    # ;lkj too be completed
    add_pkt = (
        "INSERT INTO packet "
        # "    (fileHash, pkt_datetime, pkt_epochtime, mac_addr, "
        "    (fileID, pkt_datetime, pkt_epochtime, mac_addr, "
        "     protocol, ip_ver, ip_src, ip_dst, ew, "
        "     tlp, tlp_srcport, tlp_dstport, length) "
        "SELECT "
        # "    %(fileHash)s, FROM_UNIXTIME( %(pkt_timestamp)s ), %(pkt_timestamp)s, %(mac_addr)s, "
        "    %(fileID)s, FROM_UNIXTIME( %(pkt_timestamp)s ), %(pkt_timestamp)s, %(mac_addr)s, "
        "    %(protocol)s, %(ip_ver)s, %(ip_src)s, %(ip_dst)s, %(ew)s, "
        "    %(tlp)s, %(tlp_srcport)s, %(tlp_dstport)s, %(length)s ;")

    # "    %(tlp)s, %(tlp_srcport)s, %(tlp_dstport)s, %(length)s "
    # "WHERE NOT EXISTS (SELECT * FROM packet "
    # "                  WHERE fileHash=%(fileHash)s AND pkt_epochtime=%(pkt_timestamp)s);")

    add_pkt_batch = (
        "INSERT INTO packet "
        # "    (fileHash, pkt_datetime, pkt_epochtime, mac_addr, "
        "    (fileID, pkt_datetime, pkt_epochtime, mac_addr, "
        "     protocol, ip_ver, ip_src, ip_dst, ew, "
        "     tlp, tlp_srcport, tlp_dstport, length) "
        "SELECT "
        # "    %(fileHash)s, FROM_UNIXTIME( %(pkt_timestamp)s ), %(pkt_timestamp)s, %(mac_addr)s, "
        "    %(fileID)s, FROM_UNIXTIME( %(pkt_timestamp)s ), %(pkt_timestamp)s, %(mac_addr)s, "
        "    %(protocol)s, %(ip_ver)s, %(ip_src)s, %(ip_dst)s, %(ew)s, "
        "    %(tlp)s, %(tlp_srcport)s, %(tlp_dstport)s, %(length)s; ")

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

    # Not yet in use...
    add_protocol = ("INSERT INTO protocol "
                    ## BINARY       VARCHAR   TEXT      INT       TEXT         BOOL  TEXT     INT       TEXT
                    # "(fileHash, mac_addr, protocol, src_port, dst_ip_addr, ipv6, dst_url, dst_port, notes) "
                    # INT     INT       TEXT      INT       TEXT         BOOL  TEXT     INT       TEXT
                    "(fileID, deviceID, protocol, src_port, dst_ip_addr, ipv6, dst_url, dst_port, notes) "
                    # "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);")
                    # "VALUES (%(fileHash)s, %(mac_addr)s, %(protocol), %(src_port)s, %(dst_ip_addr)s, %(ipv6)s, %(dst_url)s, %(dst_port)s, %(notes)s);")
                    "VALUES (%(fileID)s, %(deviceID)s, %(protocol), %(src_port)s, %(dst_ip_addr)s, %(ipv6)s, %(dst_url)s, %(dst_port)s, %(notes)s);")

    # Queries
    query_unique_capture = ("SELECT fileHash FROM capture;")
    # query_unique_capture = ("SELECT id FROM capture;")

    query_imported_capture = ("SELECT * FROM capture;")

    query_imported_capture_with = (
        # "SELECT DISTINCT cap.id, cap.fileName, cap.fileLoc, cap.fileHash, cap.capDate, cap.capDuration, cap.activity, cap.details "
        "SELECT DISTINCT cap.id, cap.fileName, cap.fileLoc, cap.fileHash, cap.capDate, cap.capDuration, "
        "    cap.lifecyclePhase, cap.internet, cap.humanInteraction, cap.preferredDNS, cap.isolated, "
        "    cap.durationBased, cap.duration, cap.actionBased, cap.deviceAction, cap.details "
        "FROM capture as cap "
        "    INNER JOIN ( "
        "      SELECT * FROM device_in_capture "
        # "      WHERE mac_addr=%(dev_mac)s) device "
        # "        ON device.fileHash = cap.fileHash "
        "      WHERE deviceID=%(deviceID)s) device "
        "        ON device.fileID = cap.id "
        "    INNER JOIN ( "
        "      SELECT * FROM device_in_capture "
        # "      WHERE mac_addr=%(gateway_mac)s) gateway "
        # "        ON gateway.fileHash = cap.fileHash;")
        "      WHERE deviceID=%(gatewayID)s) gateway "
        "        ON gateway.fileID = cap.id;")

    query_imported_capture_with_device = (
        # "SELECT DISTINCT cap.id, cap.fileName, cap.fileLoc, cap.fileHash, cap.capDate, cap.capDuration, cap.activity, cap.details "
        "SELECT DISTINCT cap.id, cap.fileName, cap.fileLoc, cap.fileHash, cap.capDate, cap.capDuration, "
        "    cap.lifecyclePhase, cap.internet, cap.humanInteraction, cap.preferredDNS, cap.isolated, "
        "    cap.durationBased, cap.duration, cap.actionBased, cap.deviceAction, cap.details "
        "FROM capture as cap "
        "    INNER JOIN ( "
        "      SELECT * FROM device_in_capture "
        # "      WHERE mac_addr=%(dev_mac)s) device "
        # "        ON device.fileHash = cap.fileHash;")
        "      WHERE deviceID=%(deviceID)s) device "
        "        ON device.fileID = cap.id;")

    # query_device_from_capture = ("SELECT * FROM device WHERE fileName=%s;")
    # query_device_from_capture = ("SELECT * FROM device_in_capture WHERE fileHash=%s;")
    query_device_from_capture = ("SELECT * FROM device WHERE mac_addr = ANY "
                                 # "(SELECT mac_addr FROM device_in_capture WHERE"
                                 "(SELECT deviceID FROM device_in_capture \n"
                                 # " fileHash=%s);"
                                 # " fileName=%s);")
                                 " WHERE fileID=%s);")

    query_device_from_capture_list = ("SELECT * FROM device WHERE id = ANY "
                                      "(SELECT DISTINCT deviceID FROM device_in_capture \n"
                                      " WHERE fileID IN (%s) );")

    # query_identified_devices_from_capture = ("SELECT * FROM device_in_capture "
    #                                    "WHERE fileHash = %s AND mac_addr = %s;")
    # query_identified_devices_from_capture = ("SELECT id, mac_addr, imported FROM device_in_capture "
    # query_identified_devices_from_capture = ("SELECT * FROM device_in_capture "
    query_labeled_devices_from_capture = ("SELECT * FROM device_in_capture "
                                          # "WHERE fileHash = %s;")
                                          "WHERE fileID = %s;")
    # "WHERE fileHash = %s AND imported = TRUE;")

    query_most_recent_fw_ver = ("SELECT ds.fw_ver FROM device_state AS ds "
                                "INNER JOIN "
                                # "    (SELECT capture.fileHash as fileHash "
                                "    (SELECT capture.id as fileID "
                                "     FROM capture "
                                "     INNER JOIN "
                                "         (SELECT MAX(c.capDate) as capDate "
                                "          FROM device_state as ds "
                                "          INNER JOIN "
                                # "              capture as c on ds.fileHash = c.fileHash "
                                # "          WHERE ds.mac_addr = %(mac_addr)s AND "
                                "              capture as c on ds.fileID = c.id "
                                "          WHERE ds.deviceID = %(deviceID)s AND "
                                "                c.capDate <= %(capDate)s "
                                "         ) AS q1 ON capture.capDate=q1.capDate "
                                # "     ) AS q2 ON ds.fileHash=q2.fileHash "
                                # " WHERE ds.mac_addr = %(mac_addr)s;")
                                "     ) AS q2 ON ds.fileID=q2.fileID "
                                " WHERE ds.deviceID = %(deviceID)s;")

    query_mac_to_mfr = ("SELECT * FROM mac_to_mfr;")

    query_devices = ("SELECT * FROM device;")

    # query_devices_imported = ("SELECT * FROM device WHERE not ISNULL(internalName);")
    query_devices_imported = ("SELECT id, mfr, model, mac_addr, internalName, deviceCategory "
                              "FROM device "
                              "WHERE NOT ISNULL(internalName);")

    query_devices_imported_ignore_noIPs = (
        "SELECT id, mfr, model, mac_addr, internalName, deviceCategory "
        "FROM device "
        # "WHERE internalName!=%(internalName)s AND NOT ISNULL(internalName);")
        # "WHERE mac_addr!=%(ignored_dev)s AND NOT ISNULL(internalName);")
        "WHERE mac_addr!=%(ignored_deviceID)s AND NOT ISNULL(internalName);")

    query_devices_imported_ignore_known = (
        "SELECT DISTINCT d.id, d.mfr, d.model, d.mac_addr, d.internalName, d.deviceCategory, s.ipv4_addr, s.ipv6_addr "
        "FROM device AS d "
        # "    INNER JOIN (SELECT * FROM device_state) AS s ON d.mac_addr=s.mac_addr "
        # "WHERE d.mac_addr!=%(ignored_dev)s AND NOT ISNULL(d.internalName);")
        "    INNER JOIN (SELECT * FROM device_state) AS s ON d.id=s.deviceID "
        "WHERE d.id!=%(ignored_deviceID)s AND NOT ISNULL(d.internalName);")

    query_devices_imported_ignore = (
        "SELECT DISTINCT d.id, d.mfr, d.model, d.mac_addr, d.internalName, d.deviceCategory, s.ipv4_addr, s.ipv6_addr "
        "FROM device AS d "
        # "    INNER JOIN (SELECT * FROM device_state) AS s ON d.mac_addr=s.mac_addr "
        "    INNER JOIN (SELECT * FROM device_state) AS s ON d.id=s.deviceID "
        # "WHERE d.mac_addr!=%(ignored_dev)s;")
        # "WHERE d.mac_addr!=%(ignored_dev)s AND s.ipv4_addr!='Not found';")
        # "WHERE d.mac_addr!=%(ignored_dev)s AND "
        "WHERE d.id!=%(ignored_deviceID)s AND "
        "s.ipv4_addr!='Not found' AND s.ipv4_addr!='0.0.0.0' AND "
        "s.ipv6_addr!='Not found' AND s.ipv6_addr!='::';")

    query_gateway_ips = (
        "SELECT DISTINCT ipv4_addr, ipv6_addr "
        "FROM device_state "
        # "WHERE mac_addr=%(gateway_mac)s;")
        # "WHERE mac_addr=%(gateway_mac)s AND "
        "WHERE deviceID=%(gatewayID)s AND "
        "ipv4_addr!='Not found' AND ipv4_addr!='0.0.0.0' AND "
        "ipv6_addr!='Not found' AND ipv6_addr!='::';")

    query_devices_in_caps_except = (
        "SELECT DISTINCT dc.id, d.internalName, dc.mac_addr "
        "FROM device_in_capture AS dc "
        "    INNER JOIN ( "
        "        SELECT * "
        "        FROM capture "
        "        WHERE id=%(captureID)s) AS c "
        # "    ON dc.fileHash=c.fileHash "
        "    ON dc.fileID=c.id "
        "    INNER JOIN ( "
        "        SELECT * "
        "        FROM device) AS d "
        # "    ON dc.mac_addr = d.mac_addr "
        # "WHERE dc.mac_addr != %(mac_addr)s;")
        "    ON dc.deviceID = d.id "
        "WHERE dc.deviceID != %(deviceID)s;")

    query_caps_with_device_where = (
        "SELECT DISTINCT "
        "    c.id, c.fileName, c.fileLoc, c.fileHash, c.capDate, c.capDuration, "
        "    c.lifecyclePhase, c.internet, c.humanInteraction, c.preferredDNS, c.isolated, "
        "    c.durationBased, c.duration, c.actionBased, c.deviceAction, c.details "
        "FROM capture AS c "
        "    INNER JOIN ( "
        "        SELECT * "
        "        FROM device_in_capture "
        # "        WHERE mac_addr = %(mac_addr)s) AS d "
        # "    ON c.fileHash=d.fileHash")
        "        WHERE deviceID = %(deviceID)s) AS d "
        "    ON c.id=d.fileID")
    '''
    query_caps_with_device_where = (
        "SELECT DISTINCT "
        "    c.id, c.fileName, c.fileHash, c.activity, c.capDate, c.capDuration, c.details "
        "FROM capture AS c "
        "    INNER JOIN ( "
        "        SELECT * "
        "        FROM device_in_capture "
        "        WHERE mac_addr = %(mac_addr)s) AS d "
        "    ON c.fileHash=d.fileHash")
    '''

    query_capID_where_capName = ("SELECT id FROM capture WHERE fileName=%s;")

    # query_device_info =  ("SELECT * FROM device WHERE mac_addr=%s;")
    query_device_info = ("SELECT * FROM device WHERE id=%s;")

    # query_device_macs = ("SELECT mac_addr FROM device;")
    # query_device_macs = ("SELECT id, mac_addr FROM device;")
    query_device_macs = ("SELECT id, mac_addr, unlabeled FROM device;")

    query_device_ids_from_macs = ("SELECT id, mac_addr FROM device WHERE mac_addr IN (%s);")

    # query_device_state = ("SELECT * FROM device_state WHERE fileHash=%s AND mac_addr=%s;")
    query_device_state = ("SELECT * FROM device_state WHERE fileID=%s AND deviceID=%s;")

    query_device_state_exact = ("SELECT * FROM device_state WHERE "
                                # " fileHash=%(fileHash)s AND mac_addr=%(mac_addr)s AND "
                                # " internalName=%(internalName)s AND fw_ver=%(fw_ver)s AND "
                                # " ipv4_addr=%(ipv4_addr)s AND ipv6_addr=%(ipv6_addr)s;")
                                " fileID=%(fileID)s AND deviceID=%(deviceID)s AND "
                                " fw_ver=%(fw_ver)s AND ipv4_addr=%(ipv4_addr)s AND ipv6_addr=%(ipv6_addr)s;")

    # query_device_communication = ("SELECT * FROM protocol WHERE device=%s;")
    query_device_communication = ("SELECT * FROM protocol WHERE deviceID=%s;")

    # query_device_communication_by_capture = ("SELECT * FROM protocol WHERE device=%(device)s AND fileHash=%(fileHash)s;")
    query_device_communication_by_capture = (
        "SELECT * FROM protocol WHERE deviceID=%(deviceID)s AND fileID=%(fileID)s;")

    query_pkts = ("SELECT * FROM packet;")

    # query_pkts_by_capture = ("SELECT * FROM packet WHERE fileHash=%(fileHash)s;")
    query_pkts_by_capture = ("SELECT * FROM packet WHERE fileID=%(fileID)s;")

    # query_pkts_by_capture_and_device = ("SELECT * FROM packet WHERE fileHash=%(fileHash)s AND dev...;")

    # query_pkts_by_device = ("SELECT * FROM packet WEHRE dev...;")

    # query_device_strings = ("SELECT * FROM strings WHERE device=%s;")
    query_device_strings = ("SELECT * FROM strings WHERE deviceID=%s;")

    query_last_insert_id = ("SELECT last_insert_id();")

    def __init__(self, db_config):  # =None, new_db=False):
        # if new_db:
        #    pass
        # else:
        try:
            print("Connecting to MySQL database...")
            self.cnx = mysql.connector.connect(**db_config)

            if self.cnx.is_connected():
                print("connection established.")
            else:
                print("connection failed.")

        except Error as error:
            print(error)
        # finally:
        #    self.cnx.close()
        #    print("Connection closed.")

        self.cursor = self.cnx.cursor(buffered=True)

        self.captureID_list = []
        self.deviceID_list = []

    # SQL Initialize New Database
    def init_new_database(self, db_name):
        # Create new database
        self.cursor.execute(self.new_database + db_name + ';')
        self.cnx.commit()

        # Use new database
        self.cursor.execute(self.use_database + db_name + ';')
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

    def reinit_database(self, db_name):
        # Use new database
        self.cursor.execute(self.use_database + db_name + ';')
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

    # SQL Insertion Commands
    def insert_capture(self, data_capture):
        # self.cap = CaptureDigest(data_capture.get(fpath, "none"))

        self.cursor.execute(self.add_capture, data_capture)
        self.cnx.commit()

    def insert_device(self, data_device):
        self.cursor.execute(self.add_device, data_device)
        self.cnx.commit()

    # def insert_device_unidentified(self, data_device):
    #    self.cursor.execute(self.add_device_unidentified, data_device)
    def insert_device_unlabeled(self, data_device):
        self.cursor.execute(self.add_device_unlabeled, data_device)
        self.cnx.commit()

    def insert_device_in_capture(self, data_device_in_capture):
        self.cursor.execute(self.add_device_in_capture, data_device_in_capture)
        self.cnx.commit()

    def insert_device_in_capture_unique(self, data_device_in_capture):
        self.cursor.execute(self.add_device_in_capture_unique, data_device_in_capture)
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

    # def insert_device_state_unidentified(self, data_device_state):
    #    self.cursor.execute(self.add_device_state_unidentified, data_device_state)
    def insert_device_state_unlabeled(self, data_device_state):
        self.cursor.execute(self.add_device_state_unlabeled, data_device_state)
        self.cnx.commit()

    def update_device_state(self, data_device_state):
        self.cursor.execute(self.change_device_state, data_device_state)
        self.cnx.commit()

    def insert_packet(self, data_pkt):
        self.cursor.execute(self.add_pkt, data_pkt)
        self.cnx.commit()

    def insert_packet_batch(self, pkt_batch):
        self.cursor.executemany(self.add_pkt_batch, pkt_batch)
        self.cnx.commit()

    def insert_protocol(self, data_protocol):
        self.cursor.execute(self.add_protocol, data_protocol)
        self.cnx.commit()

    # SQL Query Commands
    def select_unique_captures(self):
        self.cursor.execute(self.query_unique_capture)

    def select_imported_captures(self):
        self.cursor.execute(self.query_imported_capture)

    # def select_imported_captures_with(self, device, gateway):
    #    self.cursor.execute(self.query_imported_capture_with, devices)

    # def select_imported_captures_with(self, devices):
    #    self.cursor.execute(self.query_imported_capture_with, devices)
    def select_imported_captures_with(self, deviceIDs):
        self.cursor.execute(self.query_imported_capture_with, deviceIDs)

    # def select_imported_captures_with_device(self, device):
    #    self.cursor.execute(self.query_imported_capture_with_device, device)
    def select_imported_captures_with_device(self, deviceID):
        self.cursor.execute(self.query_imported_capture_with_device, deviceID)

    # def select_devices_from_cap(self, capture):
    #    self.cursor.execute(self.query_device_from_capture, (capture,))
    def select_devices_from_caplist(self, captureIDs):
        # self.cursor.execute(self.query_device_from_capture_list, (",".join( map(str, captureIDs) ),) )
        format_strings = ",".join(['%s'] * len(captureIDs))
        self.cursor.execute(self.query_device_from_capture_list % format_strings, tuple(captureIDs))
        self.cnx.commit()

    def select_devices_from_cap(self, captureID):
        self.cursor.execute(self.query_device_from_capture, (captureID,))

    # def select_identified_devices_from_cap(self, fileHash):
    #    self.cursor.execute(self.query_identified_devices_from_capture, (fileHash,))
    # def select_identified_devices_from_cap(self, fileID):
    #    self.cursor.execute(self.query_identified_devices_from_capture, (fileID,))
    def select_labeled_devices_from_cap(self, fileID):
        self.cursor.execute(self.query_labeled_devices_from_capture, (fileID,))

    # def select_most_recent_fw_ver(self, macdatemac):
    #    self.cursor.execute(self.query_most_recent_fw_ver, macdatemac)
    def select_most_recent_fw_ver(self, deviceID_date_deviceID):
        self.cursor.execute(self.query_most_recent_fw_ver, deviceID_date_deviceID)

    def select_mac_to_mfr(self):
        self.cursor.execute(self.query_mac_to_mfr)

    def select_devices(self):
        self.cursor.execute(self.query_devices)

    def select_devices_imported(self):
        self.cursor.execute(self.query_devices_imported)

    # def select_devices_imported_ignore(self, ignored_dev):
    #    self.cursor.execute(self.query_devices_imported_ignore, ignored_dev)
    def select_devices_imported_ignore(self, ignored_deviceID):
        self.cursor.execute(self.query_devices_imported_ignore, ignored_deviceID)

    # def select_gateway_ips(self, gateway):
    #    self.cursor.execute(self.query_gateway_ips, gateway)
    def select_gateway_ips(self, gatewayID):
        self.cursor.execute(self.query_gateway_ips, gatewayID)

    def select_devices_in_caps_except(self, condition_data):
        self.cursor.execute(self.query_devices_in_caps_except, condition_data)

    # unknown if needs to be changed
    def select_caps_with_device_where(self, mac_addr_data, conditions):
        self.cursor.execute(self.query_caps_with_device_where + conditions, mac_addr_data)

    def select_capID_where_capName(self, capName):
        self.cursor.execute(self.query_capID_where_capName, (capName,))

    # def select_device(self, mac):
    #    self.cursor.execute(self.query_device_info, (mac,))
    def select_device(self, deviceID):
        self.cursor.execute(self.query_device_info, (deviceID,))

    # def select_device_state(self, hash, mac):
    #    self.cursor.execute(self.query_device_state, (hash, mac))
    def select_device_state(self, fileID, deviceID):
        self.cursor.execute(self.query_device_state, (fileID, deviceID))

    def select_device_state_exact(self, device_state_data):
        self.cursor.execute(self.query_device_state_exact, device_state_data)

    def select_device_macs(self):
        self.cursor.execute(self.query_device_macs)

    def select_device_ids_from_macs(self, deviceMACs):
        format_strings = ",".join(['%s'] * len(self.deviceMACs))
        self.cursor.execute(self.query_device_ids_from_macs % format_strings, tuple(deviceMACs))

    # work to be done
    def select_packets(self):
        self.cursor.execute(self.query_pkts)

    def select_packets_by_capture(self, pkt_data_capture):
        self.cursor.execute(self.query_pkt_by_capture, pkt_data_capture)

    def select_packets_by_device(self, pkt_data_device):
        self.cursor.execute(self.query_pkt_by_device, pkt_data_device)

    # unknown if this should be changed
    def select_packets_by_capture_and_device(self, pkt_data):
        self.cursor.execute(self.query_pkt_by_capture_and_device, pkt_data)

    '''
    def select_device_communication(self, device):
        self.cursor.execute(self.query_device_communication, device)
    '''

    # def select_device_strings(self, device):
    #    self.cursor.execute(self.query_device_strings, device)
    def select_device_strings(self, deviceID):
        self.cursor.execute(self.query_device_strings, deviceID)

    def select_last_insert_id(self):
        self.cursor.execute(self.query_last_insert_id)

    # Capture table of interest
    def drop_cap_toi(self):
        self.cursor.execute(self.drop_capture_toi)
        self.cnx.commit()

    def create_cap_toi(self, capture=None):
        if capture == None:
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

    # def create_dev_toi(self, mac=None):
    #    if mac == None:
    def create_dev_toi(self, deviceID=None):
        if deviceID == None:
            self.cursor.execute(self.create_device_toi_all)
        else:
            # self.cursor.execute(self.create_device_toi, mac)
            self.cursor.execute(self.create_device_toi, deviceID)
        self.cnx.commit()

    # def create_dev_toi_from_deviceID_list(self):
    def create_dev_toi_from_fileID_list(self):
        # self.cursor.execute(self.create_device_toi_from_deviceID_list, ( ",".join( map(str, self.deviceID_list) ), ) )
        # format_strings = ",".join(['%s'] * len(self.deviceID_list))
        format_strings = ",".join(['%s'] * len(self.captureID_list))
        # self.cursor.execute(self.create_device_toi_from_deviceID_list % format_strings, tuple(self.deviceID_list))
        self.cursor.execute(self.create_device_toi_from_captureID_list % format_strings, tuple(self.captureID_list))
        self.cnx.commit()
        # print(self.create_device_toi_from_deviceID_list % format_strings, tuple(self.deviceID_list))
        # print(self.create_device_toi_from_captureID_list % format_strings, tuple(self.captureID_list))

    def update_dev_toi(self, deviceID):
        # self.cursor.execute(self.update_device_toi, mac)
        self.cursor.execute(self.update_device_toi, deviceID)
        self.cnx.commit()

    # Packet table of interest
    # def select_pkt_toi(self, ew):
    def select_pkt_toi(self, ew, num_pkts):
        # self.cursor.execute(self.query_packet_toi, {**ew, **{"num_pkts":num_pkts}})
        # format_strings = ",".join(['%s'] * len(self.deviceID_list))
        # self.cursor.execute(self.query_packet_toi % {"deviceIDs":format_strings, **ew, "num_pkts":num_pkts}, tuple(self.deviceID_list))# + ew["ew"] + num_pkts)

        # format_strings = ",".join(['%s'] * len(self.deviceID_list))
        # self.cursor.execute(self.query_packet_toi % {"deviceIDs":format_strings, **ew, "num_pkts":num_pkts} % tuple(self.deviceID_list))
        format_dev = ",".join(['%s'] * len(self.deviceID_list))
        format_ew = ",".join(['%s'] * len(ew))
        self.cursor.execute(
            self.query_packet_toi % {"deviceIDs": format_dev, "ew": format_ew, "num_pkts": num_pkts} % tuple(
                self.deviceID_list + ew))
        # self.cursor.execute(self.query_packet_toi % {"ew":format_ew, "num_pkts":num_pkts} % tuple(ew))

        # print(self.query_packet_toi)
        # print(self.deviceID_list)
        # print(ew)
        # print(num_pkts)
        # print(self.query_packet_toi % {"deviceIDs":format_strings, **ew, "num_pkts":num_pkts} % tuple(self.deviceID_list))

    def drop_pkt_toi(self):
        self.cursor.execute(self.drop_packet_toi)
        self.cnx.commit()

    def create_pkt_toi(self, capture):
        self.cursor.execute(self.create_packet_toi, capture)
        self.cnx.commit()

    def create_pkt_toi_from_captureID_list(self):
        format_strings = ",".join(['%s'] * len(self.captureID_list))
        # self.cursor.execute(self.create_packet_toi_from_captureID_list, (",".join( map(str, self.captureID_list) ), ) )
        self.cursor.execute(self.create_packet_toi_from_captureID_list % format_strings, tuple(self.captureID_list))
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

    def __init__(self, fpath):  # , gui=False):
        from mudpd import MudCaptureApplication
        self.api_key = MudCaptureApplication.read_api_config(self)
        if self.api_key != "":
            self.api_key = self.api_key['api_key']
            print("Fingerbank API Key: ", self.api_key)
        self.fpath = fpath
        self.fdir, self.fname = os.path.split(fpath)
        self.fsize = os.path.getsize(fpath)
        print("file size: ", self.fsize)
        self.progress = 24  # capture header
        # self.fileHash = hashlib.md5(open(fpath,'rb').read()).hexdigest()
        self.fileHash = hashlib.sha256(open(fpath, 'rb').read()).hexdigest()
        self.id = None

        ew_ip_filter = 'ip.src in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8} and ip.dst in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8}'
        ns_ip_filter = '!ip.src in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8} or !ip.dst in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8}'
        ew_ipv6_filter = 'ipv6.src in {fd00::/8} and ipv6.dst in {fd00::/8}'
        ns_ipv6_filter = '!ipv6.src in {fd00::/8} or !ipv6.dst in {fd00::/8}'

        # (ip.src in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8} and ip.dst in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8}) or (ipv6.src in {fd00::/8} and ipv6.dst in {fd00::/8})
        # ew_filter = ['(', ew_ip_filter, ') or (', ew_ipv6_filter, ')']
        ew_filter = '(ip.src in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8} and ip.dst in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8}) or (ipv6.src in {fd00::/8} and ipv6.dst in {fd00::/8})'
        # (!ip.src in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8} or !ip.dst in {192.168.0.0/16 172.16.0.0/12 10.0.0.0/8}) and (!ipv6.src in {fd00::/8} or !ipv6.dst in {fd00::/8})
        ns_filter = ['(', ns_ip_filter, ') and (', ns_ipv6_filter, ')']

        # start = datetime.now()
        self.cap = pyshark.FileCapture(fpath)
        self.dhcp_pkts = pyshark.FileCapture(fpath, display_filter='dhcp')
        self.ew_index = []
        self.cap_ew = pyshark.FileCapture(fpath, display_filter=ew_filter)
        for p in self.cap_ew:
            self.ew_index += p.number
        # stop = datetime.now()
        # print("time to open capture with pyshark = %f seconds" % (stop-start).total_seconds())

        self.capTimeStamp = self.cap[0].sniff_timestamp
        # self.capDate = self.cap[0].sniff_timestamp
        # (self.capDate, self.capTime) = self.cap[0].sniff_timestamp.split()
        (self.capDate, self.capTime) = datetime.utcfromtimestamp(float(self.capTimeStamp)).strftime(
            '%Y-%m-%d %H:%M:%S').split()

        self.capDuration = 0  # timedelta(0)

        print(self.capDate)
        print(self.capTime)

        self.uniqueIP = []
        self.uniqueIPv6 = []
        self.uniqueMAC = []
        self.modellookup = {}

        self.newDevicesImported = False
        self.labeledDev = []
        self.unlabeledDev = []

        self.ip2mac = {}

        self.uniqueIP_dst = []
        self.uniqueIPv6_dst = []

        # str(first[len(first.__dict__['layers'])-1]).split()[1].strip(":")
        self.protocol = []

        self.num_pkts = 0
        self.pkt = []

        self.pkt_info = []  # needs to be a list of dictionary
        if self.api_key != "":
            self.extract_fingerprint()
            print("Identified devices for this capture: ", self.modellookup)
        # Fastest way to get the number of packets in capture, but still slow to do
        '''
        start = datetime.now()
        self.cap.apply_on_packets(self.count)
        stop = datetime.now()
        print("time to get pkt count = %f seconds" % (stop-start).total_seconds())
        print("count = ", self.num_pkts)
        '''

        # trying to use subprocess
        # self.num_pkts = subprocess.check_output(["tcpdump -r " + fpath])

        '''
        start = datetime.now()
        #self.cap.apply_on_packets(self.import_pkts)
        self.cap.apply_on_packets(self.append_pkt)
        stop = datetime.now()
        print("time to import_packets = %f seconds" % (stop-start).total_seconds())
        '''

        # start = datetime.now()
        # self.import_pkts()
        # stop = datetime.now()
        # print("time to import_packets = %f seconds" % (stop-start).total_seconds())

        # print("cap length = ", len(self.pkt))

        '''
        start = datetime.now()
        self.cap.apply_on_packets(self.id_unique_addrs)
        stop = datetime.now()
        print("time to process_packets from object: %f seconds" % (stop-start).total_seconds())

        '''

        # Much faster than running "self.cap.apply_on_packets(self.id_unique_addrs)", but requires slower up front processing
        # start = datetime.now()

        '''
        for i, p in enumerate(self.pkt):
            if i < 2:
                print(p)
            self.id_unique_addrs(p)
        '''

        # stop = datetime.now()
        # print("time to process_packets from list: %f seconds" % (stop-start).total_seconds())

        # self.id_unique_addrs()

    '''
    def count(self, *args):
        self.num_pkts += 1;
    '''

    def import_pkts(self):
        print("in import_pkts")
        start = datetime.now()
        self.cap.apply_on_packets(self.append_pkt)
        stop_append = datetime.now()

        #:LKJ
        self.extract_pkts()
        stop_xtrct = datetime.now()
        self.id_unique_addrs()
        stop = datetime.now()
        print("Time to append:", stop_append - start)
        print("Time to extract:", stop_xtrct - stop_append)
        print("Time for full process:", stop - start)
        '''
        for i, p in enumerate(self.pkt):
            #if i < 2:
            #    print(p)
            #self.id_unique_addrs(p)
            self.id_addr(p)
        '''
        # datetime.utcfromtimestamp(float(self.capTimeStamp)).strftime('%Y-%m-%d %H:%M:%S').split()
        # print(self.pkt[0].sniff_timestamp)
        # print(self.pkt[-1].sniff_timestamp)
        self.capDuration = round(float(self.pkt[-1].sniff_timestamp) - float(self.capTimeStamp))

    #    def import_pkts(self, *args):
    def append_pkt(self, *args):
        # print("length = ", args[0].length)
        self.progress += int(args[0].length) + 16  # packet header
        # print(self.progress, "/", self.fsize)
        self.pkt.append(args[0])
        # exit()

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
        # This should be parallelizeable
        for p in self.pkt:
            self.pkt_info.append({"pkt_timestamp": p.sniff_timestamp,
                                  "mac_addr": '',
                                  "protocol": p.layers[-1].layer_name.upper(),
                                  "ip_ver": None,  # changed '-1' to None and then ''
                                  "ip_src": None,
                                  "ip_dst": None,
                                  "ew": p.number in self.ew_index,
                                  "tlp": '',
                                  "tlp_srcport": None,
                                  "tlp_dstport": None,
                                  "length": p.length})
            # "raw":p})

            '''
            self.pkt_info[-1]{"time":p.sniff_timestamp,
                              "length":p.length,
                              "protocol":p.layers[-1].layer_name.upper(),
                              "raw":p}
            '''
            for l in p.layers:
                if l.layer_name == "sll":
                    self.pkt_info[-1]["mac_addr"] = l.src_eth
                    # self.pkt_info[-1]["mac"] = l._all_fields["sll.src.eth"]
                elif l.layer_name == "eth":
                    # self.pkt_info[-1]["mac_addr"] = l.addr
                    self.pkt_info[-1]["mac_addr"] = l.src
                elif l.layer_name == "ip":
                    # self.pkt_info[-1]["ip_ver"] = l.ip.version
                    # self.pkt_info[-1]["ip_src"] = l.ip.src
                    # self.pkt_info[-1]["ip_dst"] = l.ip.dst
                    self.pkt_info[-1]["ip_ver"] = l.version
                    self.pkt_info[-1]["ip_src"] = l.src
                    self.pkt_info[-1]["ip_dst"] = l.dst
                    # self.pkt_info[-1]["ip_ver"] = l._all_fields["ip.version"]
                    # self.pkt_info[-1]["ip_src"] = l._all_fields["ip.src"]
                    # self.pkt_info[-1]["ip_dst"] = l._all_fields["ip.dst"]
                elif l.layer_name == "ipv6":
                    self.pkt_info[-1]["ip_ver"] = l.version
                    self.pkt_info[-1]["ip_src"] = l.src
                    self.pkt_info[-1]["ip_dst"] = l.dst
                elif l.layer_name == "tcp":
                    self.pkt_info[-1]["tlp"] = "tcp"
                    # self.pkt_info[-1]["tlp_srcport"] = l.tcp.srcport
                    # self.pkt_info[-1]["tlp_dstport"] = l.tcp.dstport
                    self.pkt_info[-1]["tlp_srcport"] = l.srcport
                    self.pkt_info[-1]["tlp_dstport"] = l.dstport
                    # self.pkt_info[-1]["tcp_srcport"] = l.tcp.srcport
                    # self.pkt_info[-1]["tcp_dstport"] = l.tcp.dstport
                    ##self.pkt_info[-1]["tcp_srcport"] = l._all_fields["tcp.srcport"]
                    ##self.pkt_info[-1]["tcp_dstport"] = l._all_fields["tcp.dstport"]
                    # self.pkt_info[-1]["udp_srcport"] = ''
                    # self.pkt_info[-1]["udp_dstport"] = ''
                elif l.layer_name == "udp":
                    self.pkt_info[-1]["tlp"] = "udp"
                    # self.pkt_info[-1]["tlp_srcport"] = l.udp.srcport
                    # self.pkt_info[-1]["tlp_dstport"] = l.udp.dstport
                    self.pkt_info[-1]["tlp_srcport"] = l.srcport
                    self.pkt_info[-1]["tlp_dstport"] = l.dstport
                    # self.pkt_info[-1]["udp_srcport"] = l.udp.srcport
                    # self.pkt_info[-1]["udp_dstport"] = l.udp.dstport
                    ##self.pkt_info[-1]["udp_srcport"] = l._all_fields["udp.srcport"]
                    ##self.pkt_info[-1]["udp_dstport"] = l._all_fields["udp.dstport"]
                    # self.pkt_info[-1]["tcp_srcport"] = ''
                    # self.pkt_info[-1]["tcp_dstport"] = ''
                elif l.layer_name != p.layers[-1].layer_name:
                    print("Warning: Unknown/Unsupported layer seen here:", l.layer_name)
                # could add some sort of check for the direction here, potentially. Maybe add post
                # self.pkt_info[-1]["direction"] = #n/s or e/w

    def id_unique_addrs(self):
        for p in self.pkt:
            self.id_addr(p)  # ;lkj

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

        pMAC = pMAC.upper()
        # ;lkj
        # self.pkt_info.append({})
        # self.pkt_info[-1]["mac"] = pMAC

        if pMAC not in self.uniqueMAC:
            # print(pMAC)
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
                    # print(pIPv6)
                    self.uniqueIPv6.append(pIPv6)

                # self.pkt_info[-1]["src_ip"] = pIPv6
                # self.pkt_info[-1]["ver"] = "v6"
        else:
            if (pMAC, "ipv4") not in self.ip2mac:
                self.ip2mac[(pMAC, "ipv4")] = pIP
            # Add unique IPs to the list
            if pIP not in self.uniqueIP:
                # print(pIP)
                self.uniqueIP.append(pIP)

            # self.pkt_info[-1]["src_ip"] = pIP
            # self.pkt_info[-1]["ver"] = "v4"

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
                    # print(pIPv6)
                    self.uniqueIPv6_dst.append(pIPv6_dst)
        else:
            # Add unique IPs to the list
            if pIP_dst not in self.uniqueIP_dst:
                # print(pIP)
                self.uniqueIP_dst.append(pIP_dst)

    # Need to check on what this is for (2020-02-20)
    # TBD in the future (2019-06-13)
    def load_from_db(self, fpath):
        self.fpath = fpath
        self.fdir, self.fname = os.path.split(fpath)
        # self.fileHash = hashlib.md5(open(fpath,'rb').read()).hexdigest()
        self.fileHash = hashlib.sha256(open(fpath, 'rb').read()).hexdigest()

        self.cap = pyshark.FileCapture(fpath)

        self.capTimeStamp = self.cap[0].sniff_timestamp
        (self.capDate, self.capTime) = datetime.utcfromtimestamp(float(self.capTimeStamp)).strftime(
            '%Y-%m-%d %H:%M:%S').split()

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

    def extract_fingerprint(self):
        print("Starting Fingerprint Extraction")
        if self.api_key != "":
            for p in self.dhcp_pkts:
                dhcp_fingerprint = ""
                hostname = ""
                output = ""
                yes = True
                first = True
                try:
                    mac = p.sll.src_eth
                    mac = mac.upper()
                except AttributeError:
                    print("AttributeError: Can't find MAC Address")
                try:
                    if self.modellookup[mac] == "":
                        yes = True
                    else:
                        yes = False
                except KeyError as ke:
                    print("Device not yet fingerprinted: ", ke)
                try:
                    hostname = p['DHCP'].option_hostname
                except AttributeError:
                    print("AttributeError: Can't find hostname")
                try:
                    for f in p['DHCP'].option_request_list_item.all_fields:
                        if not first:
                            dhcp_fingerprint += ","
                        first = False
                        dhcp_fingerprint += f.show
                except AttributeError:
                    print("AttributeError: Unable to find DHCP options")
                    yes = False
                except KeyError:
                    print("KeyError: Layer does not exist in packet")
                if dhcp_fingerprint == "":
                    yes = False
                    print("No fingerprint found")
                if yes:
                    output = lookup_fingerbank(dhcp_fingerprint, hostname, mac, self.api_key)
                    print("Fingerprint Result:", output["name"])
                    self.modellookup.update({mac: output["name"]})
            else:
                print("No Fingerbank API Key Present")
        print("End Fingerprint Extraction")

    # def __del__(self):
    def __exit__(self):
        self.cap.close()
        self.dhcp_pkts.close()


# Database Main (for testing purposes)
if __name__ == "__main__":

    mysql.connector.connect()

    fname = "/Users/ptw/Documents/GRA-MITRE-DDoS/captures/ecobee/ecobeeThermostat_iphone_setup.pcap"
    capture = CaptureDigest(fname)
    # import_file(fname)
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

# Adding capture things items:
# fileName
# fileLoc - manually input to generate filename, md5, and capDate
# md5
# capDate
# Activity - manual
# Details - manual

# Adding device items:
# Mfr - attempt to generate from MAC
# Model - manual
# MAC_addr - Can be located in MAC address
# internalName - manual
# Device category - manual
# MUD capable - may be able to generate this, but manual for now
# wifi #if MAC found, then wifi is set to YES
# bluetooth - manual
# zigbee - manual
# zwave - manual
# 4G - manual
# 5G - manual
# other protocols - manual
# notes - manual

# Adding Device State items:
# md5 - generated from input fileLoc
# MAC address - identified from file
# internal name (previously given)
# fw_ver - manual
# ipv4_addr - generated from file
# ipv6_addr - generated from file

# Adding Protocol items:
# md5 - generated from input fileLoc
# MAC address - generated from file
# src_port - generated from input file
# dst_ip_addr - generated from file
# ipv6 (bool) - generated from file
# dst_url - generated from file
# dst_port - generated from file
# notes - generated
