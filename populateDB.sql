USE DeviceCaptures;

INSERT INTO device
	(mfr, model, internalName, mac_addr, deviceCategory, wifi, notes)
VALUES
    ("Ecobee", "Ecobee4", "ecobee", "44:61:32:72:04:34", "Thermostat", TRUE,
    "Uses 915MHz band to communicate to sensor. Cannot connect to network due to port number being too high."),
    ("Linksys", "WRT1900ACV2", "testLinksys-IoTMUD", "24:F5:A2:B2:63:06", "Router", TRUE,
    "testLinksys-IoTMUD Network Router (MUD-enabled)");

INSERT INTO device
	(mfr, model, internalName, mac_addr, deviceCategory, 3G, 4G, wifi, bluetooth/*, otherProtocols */)
VALUES
    /*("Apple", "iPhone 6", "iphone", "20:EE:28:99:E6:FA", "Smartphone", TRUE, TRUE, TRUE, TRUE, "3G/4G"),*/
    ("Apple", "iPhone 6", "iphone", "20:EE:28:99:E6:FA", "Smartphone", TRUE, TRUE, TRUE, TRUE/*, ""*/),
    ("Samsung", "Galaxy S8", "android", "B8:D7:AF:A9:59:5F", "Smartphone", TRUE, TRUE, TRUE, TRUE/*, ""*/);

INSERT INTO capture
/*	(fileName, fileLoc, fileMD5Hash, capDate, activity, details)*/
	(fileName, fileLoc, fileHash, capDate, activity, details)
VALUES
	("ecobeeThermostat_iphone_setup.pcap", "/Users/ptw/Documents/GRA-MITRE-DDoS/captures/ecobee/",
    "8b9c2749049c3e9909f95aca8c39e9ab", "2018-12-04 11:45:37.768594", "Setup/Init",
    "Initial setup of Ecobee thermostat onto testLinksys-IoTMUD network using iPhone 6"),
    ("ecobeeThermostat_iphone_setup-skippingWifi.pcap", "/Users/ptw/Documents/GRA-MITRE-DDoS/captures/ecobee/",
    "89d7216ea471fcf10e560676100c32c5", "2018-12-04 12:41:05.538636", "Setup/Init",
    "Initial setup of Ecobee thermostat onto testLinksys-IoTMUD network using iPhone 6, skipping wifi in setup"),
    ("ecobeeThermostat_iphone_setup-wifiConfig.pcap", "/Users/ptw/Documents/GRA-MITRE-DDoS/captures/ecobee/",
    "259e80845e206f00dfd0b5531dc08557", "2018-12-04 12:21:51.548605", "Setup/Init",
    "Initial setup of Ecobee thermostat onto testLinksys-IoTMUD network using iPhone 6, attempting to use wifi");

INSERT INTO device_in_capture
	(fileName, fileHash, mac_addr)
VALUES
	("ecobeeThermostat_iphone_setup.pcap", "8b9c2749049c3e9909f95aca8c39e9ab", "20:EE:28:99:E6:FA"),
	("ecobeeThermostat_iphone_setup.pcap", "8b9c2749049c3e9909f95aca8c39e9ab", "44:61:32:72:04:34"),
    ("ecobeeThermostat_iphone_setup.pcap", "8b9c2749049c3e9909f95aca8c39e9ab", "24:F5:A2:B2:63:06"),
    ("ecobeeThermostat_iphone_setup-skippingWifi.pcap", "89d7216ea471fcf10e560676100c32c5", "20:EE:28:99:E6:FA"),
    ("ecobeeThermostat_iphone_setup-skippingWifi.pcap", "89d7216ea471fcf10e560676100c32c5", "44:61:32:72:04:34"),
    ("ecobeeThermostat_iphone_setup-skippingWifi.pcap", "89d7216ea471fcf10e560676100c32c5", "24:F5:A2:B2:63:06"),
	("ecobeeThermostat_iphone_setup-wifiConfig.pcap", "259e80845e206f00dfd0b5531dc08557", "20:EE:28:99:E6:FA"),
    ("ecobeeThermostat_iphone_setup-wifiConfig.pcap", "259e80845e206f00dfd0b5531dc08557", "44:61:32:72:04:34"),
    ("ecobeeThermostat_iphone_setup-wifiConfig.pcap", "259e80845e206f00dfd0b5531dc08557", "24:F5:A2:B2:63:06");

/* Queue of things to add to the Database */
INSERT INTO device_state
/*	(fileMD5Hash, mac_addr, fw_ver, ipv4_addr, ipv6_addr)*/
	(fileHash, mac_addr, fw_ver, ipv4_addr, ipv6_addr)
VALUES
	("8b9c2749049c3e9909f95aca8c39e9ab", "20:EE:28:99:E6:FA", "iOS 12.1.4", "", "");

SELECT * FROM device;
SELECT * FROM device_in_capture;
SELECT * FROM device_state;
SELECT * FROM capture;
/*INSERT INTO capture(capDate, capFileLoc, capFileHash, activity, details) VALUES();*/

SELECT ds.internalName, ds.fw_ver, c.capDate
FROM
	device_state as ds
		INNER JOIN
	capture as c on ds.fileHash = c.fileHash
WHERE
	ds.mac_addr = '20:EE:28:99:E6:FA' AND
	c.capDate < '2018-12-05';

INSERT INTO device_state
	(fileHash, mac_addr, fw_ver, ipv4_addr, ipv6_addr)
VALUES
	('9e87ca573940b2017fd0d338a9baee85', "20:EE:28:99:E6:FA", "iOS 19.9.9", "192.168.10.2", "");
SELECT
	q1.mac as MAC, q1.fwv as Firmware_Version, MAX(q1.cd) as most_recent_to_capture
FROM
	(SELECT
		ds.fw_ver as fwv, c.capDate as cd, ds.mac_addr as mac
	FROM
		device_state as ds
			INNER JOIN
		capture as c on ds.fileHash = c.fileHash
	WHERE
		ds.mac_addr = '20:EE:28:99:E6:FA' AND
		c.capDate < '2018-12-05') as q1
GROUP BY q1.mac;

/*Part 1*/
SELECT
		ds.id as id, ds.fw_ver as fwv, c.capDate as cd, ds.mac_addr as mac
	FROM
		device_state as ds
			INNER JOIN
		capture as c on ds.fileHash = c.fileHash
	WHERE
		ds.mac_addr = '20:EE:28:99:E6:FA' AND
		c.capDate < '2018-12-05';

SELECT
		MAX(c.capDate) as cd
	FROM
		device_state as ds
			INNER JOIN
		capture as c on ds.fileHash = c.fileHash
	WHERE
		ds.mac_addr = '20:EE:28:99:E6:FA' AND
		c.capDate < '2018-12-05';


/*Part 2*/
SELECT MAX(q1.cd) as capDate
FROM (
SELECT
		ds.id as id, ds.fw_ver as fwv, c.capDate as cd, ds.mac_addr as mac
	FROM
		device_state as ds
			INNER JOIN
		capture as c on ds.fileHash = c.fileHash
	WHERE
		ds.mac_addr = '20:EE:28:99:E6:FA' AND
		c.capDate < '2018-12-05'
) AS q1
GROUP BY q1.mac;        

/*Part 3*/
SELECT
	capture.fileHash as fileHash
FROM 
	capture
		INNER JOIN
	(SELECT
		MAX(q1.cd) as capDate
	FROM
		(SELECT
			ds.id as id, ds.fw_ver as fwv, c.capDate as cd, ds.mac_addr as mac
		FROM
			device_state as ds
				INNER JOIN
			capture as c on ds.fileHash = c.fileHash
		WHERE
			ds.mac_addr = '20:EE:28:99:E6:FA' AND
			c.capDate < '2018-12-05') AS q1
	GROUP BY q1.mac) AS q2
ON capture.capDate=q2.capDate;

/*Part 4*/
SELECT
	ds.fw_ver
FROM
	device_state AS ds
		INNER JOIN
	(SELECT
		capture.fileHash as fileHash
	FROM 
		capture
			INNER JOIN
		(SELECT
			MAX(q1.cd) as capDate
		FROM
			(SELECT
				ds.id as id, ds.fw_ver as fwv, c.capDate as cd, ds.mac_addr as mac
			FROM
				device_state as ds
					INNER JOIN
				capture as c on ds.fileHash = c.fileHash
			WHERE
				ds.mac_addr = '20:EE:28:99:E6:FA' AND
				c.capDate < '2018-12-05') AS q1
		GROUP BY q1.mac) AS q2
		ON capture.capDate=q2.capDate) AS q3
    ON ds.fileHash=q3.fileHash
WHERE
	ds.mac_addr = '20:EE:28:99:E6:FA';

/*Part 3 as Part 4*/
SELECT
	ds.fw_ver
FROM
	device_state AS ds
		INNER JOIN
	(SELECT
		capture.fileHash as fileHash
	FROM 
		capture
			INNER JOIN
		(SELECT
			MAX(c.capDate) as capDate
		FROM
			device_state as ds
				INNER JOIN
			capture as c on ds.fileHash = c.fileHash
		WHERE
			ds.mac_addr = '26:f5:a2:b2:63:06' AND /*'20:EE:28:99:E6:FA' AND*/
			c.capDate <= '2018-10-25 17:02:34'
		) AS q1 ON capture.capDate=q1.capDate) AS q2
    ON ds.fileHash=q2.fileHash
WHERE
	ds.mac_addr = '26:f5:a2:b2:63:06';/*'20:EE:28:99:E6:FA';*/

SELECT capDate FROM capture WHERE fileHash='9e87ca573940b2017fd0d338a9baee85';






SELECT q2.id, ds.fw_ver as Firmware_Version
FROM device_state ds
INNER JOIN (
SELECT
	q1.id as id, q1.mac as MAC, MAX(q1.cd) as most_recent_to_capture
FROM
	(SELECT
		ds.id as id, ds.fw_ver as fwv, c.capDate as cd, ds.mac_addr as mac
	FROM
		device_state as ds
			INNER JOIN
		capture as c on ds.fileHash=c.fileHash
	WHERE
		ds.mac_addr = '20:EE:28:99:E6:FA' AND
		c.capDate <= '2018-12-05') as q1
GROUP BY q1.mac) q2 ON q2.id=ds.id;


/*SELECT HEX(fileMD5Hash) from capture;
SELECT fileMD5Hash from capture;*/
SELECT HEX(fileHash) from capture;
SELECT fileHash from capture;

SELECT
	*
FROM
	device
WHERE
	mac_addr = ANY
    (SELECT
		mac_addr
	FROM
		device_in_capture
	WHERE
		fileHash="8b9c2749049c3e9909f95aca8c39e9ab");
SELECT * FROM device_in_capture WHERE fileHash="8b9c2749049c3e9909f95aca8c39e9ab";

SELECT * FROM capture;
DELETE FROM capture WHERE id=8;
/*
SELECT * FROM device_in_capture;
DELETE FROM device WHERE id=9;
DELETE FROM device_in_capture WHERE id=19;
*/

SELECT * FROM device_in_capture WHERE fileHash="8b9c2749049c3e9909f95aca8c39e9ab";
DELETE FROM device_state WHERE id=10 or id=13;

SELECT * FROM device_state;

UPDATE device_state
SET fw_ver = "iOS 18.8.8"
WHERE mac_addr='20:EE:28:99:E6:FA' AND fileHash='9e87ca573940b2017fd0d338a9baee85';

SELECT * from device;
DELETE FROM device WHERE id=20;
SELECT * from device_state;
SELECT * from device_in_capture;
DELETE FROM device_in_capture WHERE id=37;


























