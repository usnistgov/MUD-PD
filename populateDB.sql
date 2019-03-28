INSERT INTO device
	(mfr, model, internalName, mac_addr, deviceCategory, wifi, notes)
VALUES
    ("Ecobee", "Ecobee4", "ecobee", "44:61:32:72:04:34", "Thermostat", TRUE,
    "Uses 915MHz band to communicate to sensor. Cannot connect to network due to port number being too high."),
    ("Linksys", "WRT1900ACV2", "testLinksys-IoTMUD", "24:F5:A2:B2:63:06", "Router", TRUE,
    "testLinksys-IoTMUD Network Router (MUD-enabled)");

INSERT INTO device
	(mfr, model, internalName, mac_addr, deviceCategory, 4G, wifi, bluetooth, otherProtocols)
VALUES
    ("Apple", "iPhone 6", "iphone", "20:EE:28:99:E6:FA", "Smartphone", TRUE, TRUE, TRUE, "3G/4G"),
    ("Samsung", "Galaxy S8", "android", "B8:D7:AF:A9:59:5F", "Smartphone", TRUE, TRUE, TRUE, "3G/4G");

INSERT INTO capture
	(fileName, fileLoc, fileMD5Hash, capDate, activity, details)
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

/* Queue of things to add to the Database */
INSERT INTO device_state
	(fileMD5Hash, mac_addr, fw_ver, ipv4_addr, ipv6_addr)
VALUES
	("8b9c2749049c3e9909f95aca8c39e9ab", "20:EE:28:99:E6:FA", "iOS 12.1.4", "", "");

SELECT * FROM device;

SELECT * FROM capture;
/*INSERT INTO capture(capDate, capFileLoc, capFileHash, activity, details) VALUES();*/