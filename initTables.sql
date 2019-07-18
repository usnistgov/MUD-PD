USE DeviceCaptures;
/**
DROP TABLE capture;
DROP TABLE device_in_capture;
DROP TABLE mac_to_mfr;
DROP TABLE device;
DROP TABLE device_state;
DROP TABLE packet;
DROP TABLE protocol;
/**/

CREATE TABLE capture (
    id INT PRIMARY KEY AUTO_INCREMENT,
    fileName TEXT,
    fileLoc TEXT,
	/*fileMD5Hash BINARY(32) UNIQUE,*/
    fileHash VARCHAR(32) UNIQUE,
    /*fileMD5Hash VARCHAR(32) UNIQUE,*/
    capDate DATETIME,
    activity TEXT,
    details TEXT
);

CREATE TABLE device_in_capture (
 	id INT PRIMARY KEY AUTO_INCREMENT,
	fileName TEXT,
	fileHash VARCHAR(32),
    /*device_mac VARCHAR(17) UNIQUE*/
    mac_addr VARCHAR(17)
	/*imported BOOL DEFAULT FALSE*/
);

CREATE TABLE mac_to_mfr (
	id INT PRIMARY KEY AUTO_INCREMENT,
    mac_prefix VARCHAR(8) UNIQUE,
    mfr TEXT
);

CREATE TABLE device (
    id INT PRIMARY KEY AUTO_INCREMENT,
    mfr TEXT,
    model TEXT,
    mac_addr VARCHAR(17) UNIQUE,
    internalName VARCHAR(20) UNIQUE,
    deviceCategory TEXT,
    mudCapable BOOL DEFAULT FALSE,
    wifi BOOL DEFAULT FALSE,
    bluetooth BOOL DEFAULT FALSE,
    3G BOOL DEFAULT FALSE,
    4G BOOL DEFAULT FALSE,
    5G BOOL DEFAULT FALSE,
    zigbee BOOL DEFAULT FALSE,
    zwave BOOL DEFAULT FALSE,
    otherProtocols TEXT,
    notes TEXT
);

CREATE TABLE device_state (
    id INT AUTO_INCREMENT KEY,
	/*fileMD5Hash BINARY(32),*/
    fileHash VARCHAR(32),
    /*fileMD5Hash VARCHAR(32),*/
    mac_addr VARCHAR(17),
    internalName VARCHAR(20),
    fw_ver TEXT,
    ipv4_addr VARCHAR(15),
    ipv6_addr TEXT
);

CREATE TABLE packet (
	id INT AUTO_INCREMENT KEY,
    fileHash VARCHAR(32),
    pkt_time DATETIME, /*Should this also be unique?*/
    mac_addr VARCHAR(17),
    protocol TEXT,
    ip_ver INT,
    ip_src TEXT,
    ip_dst TEXT,
    ew BOOL,
    tlp TEXT,
    tlp_srcport INT,
    tlp_dstport INT,
    pkt_length INT,/*
    tcp_srcport INT,
    tcp_dstport INT,
    udp_srcport INT,
    udp_dstport INT,*/
    raw TEXT/*BINARY*/
);


CREATE TABLE protocol (
	id INT AUTO_INCREMENT KEY,
	/*fileMD5Hash BINARY(32),*/
    fileHash VARCHAR(32),
	/*fileMD5Hash VARCHAR(32),*/
    mac_addr VARCHAR(17),
    protocol TEXT,
    src_port INT,
    dst_ip_addr TEXT,
    ipv6 BOOL DEFAULT FALSE, /*Note: if not ipv6, then ipv4 (vice versa)*/
    dst_url TEXT,
    dst_port INT,
    notes TEXT
);