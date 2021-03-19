#!/usr/bin/python3

import json
import os
import tempfile

        
class MUDgeeWrapper:
    def __init__(self, **kwargs):

        self.config = dict()
        self.config["defaultGatewayConfig"] = {}
        self.config["deviceConfig"] = {}
        self.config["pcapLocation"] = ''

        if len(kwargs) == 0:
            self.config = {
                "defaultGatewayConfig": {
                    "macAddress": '',
                    "ipAddress": "192.168.1.1",
                    "ipv6Address": "fe80::1"
                    },

                "deviceConfig": {
                    "device": '',
                    "deviceName": ''
                    },

                "pcapLocation": ''
                }
        else:
            for key, value in kwargs.items():
                if key in ["macAddress", "ipAddress", "ipv6Address"]:
                    self.config["defaultGatewayConfig"][key] = value
                elif key in ["device", "deviceName"]:
                    self.config["deviceConfig"][key] = value
                elif key == "pcapLocation":
                    self.config[key] = value
                else:
                    print("Invalid key")

    def set_gateway(self, mac='', ip="192.168.0.1", ipv6="fe80::1"):
        self.config["defaultGatewayConfig"]["macAddress"] = mac
        self.config["defaultGatewayConfig"]["ipAddress"] = ip
        self.config["defaultGatewayConfig"]["ipv6Address"] = ipv6

    def set_device(self, mac='', name="iot_dev"):
        self.config["deviceConfig"]["device"] = mac
        self.config["deviceConfig"]["deviceName"] = name

    def set_pcap_location(self, pcap_path='./temp_config.json'):
        self.config["pcapLocation"] = pcap_path

    def write_config(self, dest_path="./mud_config.json"):
        with open(dest_path, 'w') as fp:
            json.dump(self.config, fp)

    def gen_mudfile(self, capture_files):
        print("capture_files:", capture_files)
        print("len(cap_files):", len(capture_files))
        with tempfile.TemporaryDirectory() as temp_dir:
            # Merge capture files
            merge_command = 'mergecap -w ' + temp_dir + '/merged_caps.pcap' + \
                            ' %s'*len(capture_files) % tuple(capture_files)
            print('merge_command', merge_command)
            os.system(merge_command)

            # Create configuration file for MUDGEE
            self.set_pcap_location(pcap_path=(temp_dir + '/merged_caps.pcap'))
            self.write_config(dest_path=(temp_dir + '/temp_config.json'))

            # Generate MUD File with MUDGEE
            print("Generating MUD file using MUDgee")
            config_command = 'java -jar ../mudgee/target/mudgee-1.0.0-SNAPSHOT.jar ' + temp_dir + '/temp_config.json'
            os.system(config_command)

            # Move MUD File from MUDGEE
            print("Moving MUD file from MUDgee to mudpi/mudpd")
            if not os.path.exists("./mudfiles"):
                os.mkdir("./mudfiles")
            mv_command = 'mv result/ mudfiles/'
            os.system(mv_command)