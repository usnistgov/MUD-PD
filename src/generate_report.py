#!/usr/bin/python3

## Datatypes
# device_info = {'name':<internal_name>, 'mac':<mac_address>}
#
# capture_info = {'filename':<internal_name>,
#                 'sha256':<SHA256 Hash of file>,
#                 'activity':<activity captured>,
#                 'start_time':<time capture started>,
#                 'end_time':<time capture stopped>,
#                 'duration':<duration of capture>,
#                 'internet':<Boolean state of internet access>,
#                 'other_devices':
#                     [{'name':<internal name_0>, 'mac':<mac address_0>},
#                      {'name':<internal name_1>, 'mac':<mac address_1>},
#                       ...
#                      {'name':<internal name_N>, 'mac':<mac address_N>}]
#                }
#
# communication_info = {'devices':
#                           ['name':<internal_name>,
#                            'mac':<mac_address>,
#                            'ip':[ip_0, ip_1, ..., ip_N],
#                            'protocols':['protocol':<protocol_0>,
#                                         'ingress':{'src_port':<source port (out of main device)>,
#                                                    'dst_port':<destination port (into this device)>}
#                                         'egress':{'src_port':<source port (out of this device)>,
#                                                   'dst_port':<destination port (into the main device)>},
#                                         ...]
#                            ...]
#                       'servers':
#                           ['hostname':<attempted resolve of ip to hostname>,
#                            'mac':<mac_address>,
#                            'ip':[ip_0, ip_1, ..., ip_N],
#                            'protocols':['protocol':<protocol_0>,
#                                         'ingress':{'src_port':<source port (out of main device)>,
#                                                    'dst_port':<destination port (into this device)>}
#                                         'egress':{'src_port':<source port (out of this device)>,
#                                                   'dst_port':<destination port (into the main device)>},
#                                         ...]
#                            ...]
#                           }

from datetime import datetime

class GenerateReport():
    self.header = 'This document serves to indicate the devices and operations captured in addition to any specific procedures or environmental details of the captures that differs from the general procedure found in the main README.txt'

    def __init__(self, device_info):
        self.date = datetime.today().date()
        self.device_info = device_info
        self.file = '../reports/' + device_info['name'] + '_' + self.date
        '''
        self.comm_info{'devices':[],'serv':[]}
        '''

    def write_header(self):
        with open(self.file, 'w') as f:
            f.write(self.header)
            f.write()
            f.write('Device:\t' + device_info['name'])
            f.write('MAC:\t' + device_info['mac'])

    def write_capture_info(self, capture_info):
        with open(self.file, 'a') as f:
            f.write()
            f.write('Capture File:\t' + capture_info['filename'])
            f.write('SHA256 Hash:\t' + capture_info['sha256'])
            f.write('Activity:\t' + capture_info['activity'])
            f.write('Start Time:\t' + capture_info['start_time'])
            f.write('End Time:\t' + capture_info['end_time'])
            f.write('Duration:\t' + capture_info['duration'])
            f.write('Internet:\t' + capture_info['internet'])
            f.write('Other Devices:')

            for dev in capture_info['other_devices']:
                f.write('    Name:\t' + dev['name'])
                f.write('    MAC:\t' + dev['mac'])
                f.write()

    '''
    def prepare_communication_info(self, ew, communication_info):
        if ew:
            self.comm_info{'devices'}.append(communication_info)
        else:
            self.comm_info{'serv'}.append(communication_info)
    '''

    #def write_communication_info(self):
    def write_communication_info(self, communication_info):
        with open(self.file, 'a') as f:
            f.write()
            f.write('Devices (E/W):')
            #for dev in self.comm_info['devices']:
            for dev in communication_info['devices']:
                f.write('Name:\t' + dev['other_devices']['name'])
                f.write('MAC Address:\t' + dev['other_devices']['mac'])
                f.write('Manufacturer:\t' + dev['other_devices']['mfr'])

                f.write('IP Addresses:')
                for ip in dev['ip']:
                    f.write('\t' + ip)
                
                f.write('Protocols')
                for protocol in dev['protocols']:
                    f.write(protocol['protocol'])
                    f.write('Ingress:')
                    f.write('  Port In:\t' + protocol['ingress']['port_in'])
                    f.write('  Port Out:\t' + protocol['ingress']['port_out'])
                    f.write('Egress:')
                    f.write('  Port In:\t' + protocol['egress']['port_in'])
                    f.write('  Port Out:\t' + protocol['egress']['port_out'])
                    f.write()

                           
            f.write('Servers/Services (N/S):')
            #for serv in self.comm_info['serv']:
            for serv in communication_info['serv']:
                f.write('Hostname:\t' + serv['hostname'])
                f.write('MAC:\t' +  serv['mac'])
                
                f.write('IP Addresses:')
                for ip in dev['ip']:
                    f.write('\t' + ip)
                
                f.write('Protocols')
                for protocol in dev['protocols']:
                    f.write(protocol['protocol'])
                    f.write('Ingress:')
                    f.write('  Port In:\t' + protocol['ingress']['port_in'])
                    f.write('  Port Out:\t' + protocol['ingress']['port_out'])
                    f.write('Egress:')
                    f.write('  Port In:\t' + protocol['egress']['port_in'])
                    f.write('  Port Out:\t' + protocol['egress']['port_out'])
                    f.write()
                           
