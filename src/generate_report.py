#!/usr/bin/python3

#############
# Datatypes #
#############
# device_info = {'name':<internal_name>, 'mac':<mac_address>}
#
# capture_info = {'filename':<internal_name>,
#                 'sha256':<SHA256 Hash of file>,
#                 'activity':<activity captured>,
#                 'modifiers':[<modifier0>, <modifier1>,...,<modiferN>],
#                 'start_time':<time capture started>,
#                 'end_time':<time capture stopped>,
#                 'capDuration':<duration of capture>,
#                # 'internet':<Boolean state of internet access>, #DEPRECATED
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

from datetime import datetime, timedelta
import logging
import os


class ReportGenerator:

    def __init__(self, device_info):
        self.logger = logging.getLogger(__name__)
        self.header = 'This document serves to indicate the devices and operations captured ' \
                      'in addition to any specific procedures or environmental details of the captures ' \
                      'that differs from the general procedure found in the main README.txt'
        self.date = datetime.today().date()
        self.device_info = device_info
        dir_reports = 'reports/'
        # Check if the reports directory exists
        if not os.path.isdir(dir_reports):
            os.mkdir(dir_reports)
        self.file = dir_reports + self.device_info['name'] + '_' + str(self.date) + '.txt'

    def write_header(self):
        with open(self.file, 'w') as f:
            f.write(self.header)
            f.write('\n')
            f.write('Device:\t%s\n' % self.device_info['name'])
            f.write('MAC:\t%s\n' % self.device_info['mac'])

    # Need to add modifiers, end time, and duration to database
    def write_capture_info(self, capture_info):
        with open(self.file, 'a') as f:
            f.write('\n')
            f.write('Capture File:\t%s\n' % capture_info['filename'])
            f.write('SHA256 Hash:\t%s\n' % capture_info['sha256'])
            f.write('Device Phase:\t%s\n' % capture_info['phase'])
            f.write('Environmental Variables:\n')
            f.write('    Internet Enabled       %s\n' % bool(capture_info['internet']))
            f.write('    Human Interaction      %s\n' % bool(capture_info['humanInteraction']))
            f.write('    Preferred DNS Enabled  %s\n' % bool(capture_info['preferredDNS']))
            f.write('    Device Isolated        %s\n' % bool(capture_info['isolated']))
            f.write('    Controller/Hub         %s\n' % bool(capture_info['controllerHub']))
            f.write('    Same Manufacturer      %s\n' % bool(capture_info['mfrSame']))
            f.write('    Full Network           %s\n' % bool(capture_info['fullNetwork']))
            f.write('    Physical Changes       %s\n' % bool(capture_info['physicalChanges']))
            f.write('Action-based Capture:\t%s\n' % bool(capture_info['actionBased']))
            if capture_info['actionBased']:
                f.write('    Action:\t%s\n' % capture_info['deviceAction'])
            f.write('Duration-based Capture:\t%s\n' % bool(capture_info['durationBased']))

            if capture_info['durationBased']:
                f.write('    Intended Duration:\t%s\n' % capture_info['duration'])
                f.write('    Actual Duration:\t%s\n' % str(timedelta(seconds=capture_info['capDuration'])))
                f.write('Start Time:\t%s\n' % str(capture_info['start_time']))
                f.write('End Time:\t%s\n' % str(capture_info['end_time']))
            else:
                f.write('Start Time:\t%s\n' % str(capture_info['start_time']))
                f.write('End Time:\t%s\n' % str(capture_info['end_time']))
                f.write('Actual Duration:\t%s\n' % str(timedelta(seconds=capture_info['capDuration'])))

            f.write('Other Devices:\n')

            for dev in capture_info['other_devices']:
                self.logger.info("dev: %s", dev)
                f.write('    Name:  %s\n' % str(dev['name']))
                f.write('     MAC:  %s\n' % dev['mac'])

            f.write('Notes:\n\t%s\n' % capture_info['details'])

    def write_communication_info(self, communication_info):
        with open(self.file, 'a') as f:
            f.write('\n')
            f.write('Devices (E/W):\n')
            for dev in communication_info['devices']:
                f.write('Name:\t%s\n' % dev['other_devices']['name'])
                f.write('MAC Address:\t%s\n' % dev['other_devices']['mac'])
                f.write('Manufacturer:\t%s\n' % dev['other_devices']['mfr'])

                f.write('IP Addresses:')
                for ip in dev['ip']:
                    f.write('\t%s\n' % ip)
                
                f.write('Protocols')
                for protocol in dev['protocols']:
                    f.write(protocol['protocol'] + '\n')
                    f.write('Ingress:\n')
                    f.write('  Port In:\t%s\n' % protocol['ingress']['port_in'])
                    f.write('  Port Out:\t%s\n' % protocol['ingress']['port_out'])
                    f.write('Egress:\n')
                    f.write('  Port In:\t%s\n' % protocol['egress']['port_in'])
                    f.write('  Port Out:\t%s\n' % protocol['egress']['port_out'])
                    f.write('\n')

            f.write('Servers/Services (N/S):')
            for serv in communication_info['serv']:
                f.write('Hostname:\t%s\n' % serv['hostname'])
                f.write('MAC:\t%s\n' % serv['mac'])
                
                f.write('IP Addresses:')
                for ip in dev['ip']:
                    f.write('\t%s\n' % ip)
                
                f.write('Protocols')
                for protocol in dev['protocols']:
                    f.write(protocol['protocol\n'])
                    f.write('Ingress:\n')
                    f.write('  Port In:\t%s\n' % protocol['ingress']['port_in'])
                    f.write('  Port Out:\t%s\n' % protocol['ingress']['port_out'])
                    f.write('Egress:\n')
                    f.write('  Port In:\t%s\n' % protocol['egress']['port_in'])
                    f.write('  Port Out:\t%s\n' % protocol['egress']['port_out'])
                    f.write('\n')
