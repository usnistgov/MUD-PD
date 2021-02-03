import json
import os
import struct
import subprocess


def parse_comment(comment):
    try:
        envi_dict = json.loads(comment)
    except json.decoder.JSONDecodeError:
        raise TypeError('Comment field is not in dictionary format compatible with environment variable format')

    # TODO: Check for appropriate fields

    return envi_dict


def extract_comment(filename):
    file = open(filename, 'rb')

    # Discard beginning of header
    file.read(44)

    # Check for presence of comment
    if not struct.unpack('<H', file.read(2))[0]:
        return

    # Get COMMENT LENGTH
    comment_length = struct.unpack('<H', file.read(2))[0]

    # Read COMMENT
    comment = file.read(comment_length).decode('utf-8')

    print(comment)
    file.close()
    return comment


def is_pcapng(file):
    ret = subprocess.run('file ' + file, shell=True, capture_output=True)

    # TODO: Make sure this isn't macOS specific
    if b': pcap-ng capture file ' in ret.stdout:
        return True
    else:
        return False


def is_pcap(file):
    #if not is_pcapng(file):
    #    if b': tcpdump capture file' in ret.std
    ret = subprocess.run('file ' + file, shell=True, capture_output=True)

    # TODO: Make sure this isn't too specific
    if b': tcpdump capture file' in ret.stdout:
        return True
    else:
        return False


def insert_comment(filename_in, comment, filename_out=None):
    # Double check if PcapNg file. If not, make a copy of pcap file as PcapNg
    if not is_pcapng(filename_in):
    #if filename_in.lower().endswith(".pcap"):
        fname_in = filename_in + ".pcapng"
        subprocess.call('tshark -F pcapng -r ' + filename_in + ' -w ' + fname_in, stderr=subprocess.PIPE, shell=True)
    else:
        fname_in = filename_in

    #file_in = open(filename_in, 'rb')
    file_in = open(fname_in, 'rb')

    if filename_out is None:
        filename, file_ext = os.path.splitext(fname_in)  # filename_in)
        filename_out = filename + '_commented' + file_ext

    file_out = open(filename_out, 'wb')

    # TODO: CHECK IF COMMENT ALREADY EXISTS

    # Copy first header
    header = file_in.read(4)
    file_out.write(header)

    # Replace HEADER END ADDRESS
    end_address_in = struct.unpack('<L', file_in.read(4))[0]
    # TODO: Figure out how to calculate end address
    comment_length_out = len(comment)
    end_address_out = end_address_in + comment_length_out
    if end_address_out % 8 != 0:
        padding_out = 8 - end_address_out % 8
        end_address_out += padding_out
    else:
        padding_out = 0

    file_out.write(struct.pack('<L', end_address_out))

    # Copy next header segment
    header = file_in.read(36)
    file_out.write(header)

    # Check comment presence:
    comment_present = struct.unpack('<L', file_in.read(4))[0]
    if comment_present != 0:
        # TODO: Soften Error to Warning
        # TODO: Check for error in calling function to offer solution to force overwrite
        raise ValueError('Comment already exists.')

    # Replace COMMENT LENGTH
    file_out.write(struct.pack('<H', 1))  # Write comment present
    file_out.write(struct.pack('<H', comment_length_out))  # Write comment length

    # Insert Comment
    file_out.write(bytes(comment, 'utf-8'))

    # TODO Replace PADDING to 8-byte boundary
    file_in.read(4)
    file_out.write(b'\x00'*padding_out)

    # Insert HEADER END ADDRESS
    file_out.write(struct.pack('<L', end_address_out))

    # Copy Remaining Data
    data = file_in.read(1024*1024)
    while data:
        file_out.write(data)
        data = file_in.read(1024*1024)

    file_in.close()
    file_out.close()


if __name__ == '__main__':
    envi_vars = {'internet': True,
                 'isolated': False}
    comment_envi = json.dumps(envi_vars)
    insert_comment('ietf-hackathon_pieces_nocomment.pcapng', comment_envi, 'testx.pcapng')

    comment_xtrcted = extract_comment('testx.pcapng')

    parse_comment(comment_xtrcted)
