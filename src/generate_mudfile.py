#!/usr/bin/python3

import pyshark
import os
import tempfile

'''
def merge_captures(capture_files):
    path = os.getcwd() + '/tmp'

    try:
        os.mkdir(path)
    except OSError:
        print("Creation of the directory %s failed" % path)
        return
'''

def gen_mudfile(config, capture_files):
    
    with tempfile.TemporaryDirectory() as dir:
        # Merge capture files
        merge_command = 'mergecap -w ' + dir + '/merged_caps.pcap' + ' %s'*len(capture_files) % capture_files
        print('merge_command', merge_command)
        os.system(merge_command)

        # Create configuration file for MUDGEE
        config['pcapLocation'] = os.getcwd() + '/' + dir + '/merged_caps.pcap'
        with open(dir + '/temp_config.json', 'w') as fp:
            json.dump(config, fp)

        # Generate MUD File with MUDGEE
        config_command = 'java -jar ../mudgee/target/mudgee-1.0.0-SNAPSHOT.jar ' + dir + '/temp_config.json'
        os.system(config_command)

        # Move MUD File from MUDGEE
        mv_command = 'mv ../mudgee/results/* mudfiles/'
        
        
