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

SELECT * FROM capture;
/*INSERT INTO capture(capDate, capFileLoc, capFileHash, activity, details) VALUES();*/

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
