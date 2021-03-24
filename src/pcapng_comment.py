import json
import logging
import os
import re
import struct
import subprocess


def parse_comment(comment):
    logger = logging.getLogger(__name__)
    if comment is None:
        logger.info("No JSON formatted comment exists")
        return None
    try:
        envi_dict = json.loads(comment)
    except json.decoder.JSONDecodeError:
        logger.error("Comment field is not in dictionary format compatible with environment variable format")
        raise TypeError("Comment field is not in dictionary format compatible with environment variable format")

    # TODO: Check for appropriate fields

    return envi_dict


# Borrowed from: https://stackoverflow.com/questions/5508509/how-do-i-check-if-a-string-is-valid-json-in-python
def is_json(string):
    logger = logging.getLogger(__name__)
    try:
        json.loads(string)  # Formerly set equal to "json_object"
    except ValueError as e:
        # print("Error:", e)
        logger.error("%s", e)
        return False
    return True


def get_comment_length(filename, option_type=1, json_only=True):
    file = open(filename, 'rb')

    # Discard Block Type (because assumed pcapng file)
    file.read(4)

    # Get block total length
    block_length = struct.unpack('<L', file.read(4))[0]

    # Discard byte-order magic
    file.read(4)
    # Discard major and minor versions
    file.read(4)
    # TODO: Correct this so it handles lengths other than -1
    # Discard Section Length (Typically 32 bit -1)
    file.read(16)

    remaining_header = block_length - 32

    # Get first option type and length and decrement the remaining header byte count
    opt_type = struct.unpack('<H', file.read(2))[0]
    opt_length = struct.unpack('<H', file.read(2))[0]
    remaining_header -= 4

    # Loop through remaining header to check each option if comment
    while remaining_header > 0 and opt_type != 0:
        # Process comment (opt_type = 1)
        if opt_type == option_type:
            opt_length = struct.unpack('<H', file.read(2))[0]
            remaining_header -= 2

            # Read COMMENT
            comment = file.read(opt_length).decode('utf-8')

            # Check if ONLY JSON is acceptable
            if json_only:
                # Check if Comment is JSON
                if is_json(comment):
                    # TODO: Check if the JSON is the one of interest. If there are more than one json formatted comment,
                    #  and the first on is not the one of interest, then it will be unreachable
                    file.close()
                    return opt_length
            else:
                file.close()
                return opt_length

        # Decrement remaining header based on opt_length and padding
        padding = 4 - opt_length % 4
        if padding == 4:
            padding = 0
        # Discard padding
        else:
            file.read(padding)
        remaining_header -= (opt_length + padding)

        # Read next option type and length and adjust remaining header
        opt_type = struct.unpack('<H', file.read(2))[0]
        opt_length = struct.unpack('<H', file.read(2))[0]
        remaining_header -= 4

    file.close()
    return None


# TODO: May want to rename this as "extract option", but right now only using this for specific json formatted comment
def extract_comment(filename, option_type=1, json_only=True):
    file = open(filename, 'rb')

    file.read(4)

    # Get block total length
    block_length = struct.unpack('<L', file.read(4))[0]

    # Discard byte-order magic
    file.read(4)  # byte order magic
    # Discard major and minor versions
    file.read(2)  # major version
    file.read(2)  # minor version
    # TODO: Enable the ability to handle lengths other than -1
    # Discard Section Length (Typically 64 bit -1)
    file.read(8)  # section length

    remaining_header = block_length - 24

    # Get first option type and length and decrement the remaining header byte count
    opt_type = struct.unpack('<H', file.read(2))[0]
    opt_length = struct.unpack('<H', file.read(2))[0]
    remaining_header -= 4

    # Loop through remaining header to check each option if comment
    while remaining_header > 0 and opt_type != 0:
        # Process comment (opt_type = 1)
        if opt_type == option_type:
            # Read COMMENT
            comment = file.read(opt_length).decode('utf-8')

            # Check if ONLY JSON is acceptable
            if json_only:
                # Check if Comment is JSON
                if is_json(comment):
                    # TODO: Check if the JSON is the one of interest. If there are more than one json formatted comment,
                    #  and the first on is not the one of interest, then it will be unreachable
                    file.close()
                    return json.loads(comment)
            else:
                file.close()
                return comment

        # Decrement remaining header based on opt_length and padding
        padding = 4 - opt_length % 4
        if padding == 4:
            padding = 0
        # Discard padding
        else:
            file.read(padding)
        remaining_header -= (opt_length + padding)

        # Read next option type and length and adjust remaining header
        opt_type = struct.unpack('<H', file.read(2))[0]
        opt_length = struct.unpack('<H', file.read(2))[0]
        remaining_header -= 4

    file.close()
    if json_only:
        return {}
    else:
        return ""


def is_pcapng(file):
    ret = subprocess.run('file ' + file, shell=True, capture_output=True)

    # TODO: Make sure this isn't macOS specific
    if b': pcap-ng capture file ' in ret.stdout:
        return True
    else:
        return False


def is_pcap(file):
    ret = subprocess.run('file ' + file, shell=True, capture_output=True)

    # TODO: Make sure this isn't OS-specific
    if b': tcpdump capture file' in ret.stdout:
        return True
    else:
        return False


def insert_comment(filename_in, comment, filename_out=None):

    if type(comment) is dict:
        comment = json.dumps(comment, indent=4)
    elif type(comment) is not str:
        raise TypeError("Comment must be of type 'str' or 'dict'")

    opt_comment = 1

    # Double check if PcapNg file. If not, make a copy of pcap file as PcapNg
    if not is_pcapng(filename_in):
        fname_in = filename_in.replace(".pcap", ".pcapng")
        subprocess.call('tshark -F pcapng -r ' + re.escape(filename_in) + ' -w ' + re.escape(fname_in),
                        stderr=subprocess.PIPE, shell=True)
        comment_length_old = 0
    else:
        fname_in = filename_in
        comment_length_old = get_comment_length(filename_in)
        if comment_length_old is None:
            comment_length_old = 0

    file_in = open(fname_in, 'rb')  # re.escape(fname_in), 'rb')

    if filename_out is None:
        filename, file_ext = os.path.splitext(fname_in)  # filename_in)
        filename_out = filename + '_commented' + file_ext

    file_out = open(filename_out, 'wb')  # re.escape(filename_out), 'wb')

    # Copy first header (Block type)
    header = file_in.read(4)
    file_out.write(header)

    # Replace BLOCK TOTAL LENGTH
    block_length_old = struct.unpack('<L', file_in.read(4))[0]
    comment_length_new = len(comment)
    block_length_new = block_length_old + (comment_length_new - comment_length_old) + 4
    if block_length_new % 4 != 0:
        comment_padding_new = 4 - block_length_new % 4
        block_length_new += comment_padding_new
    else:
        comment_padding_new = 0

    # Get length of old comment padding
    if comment_length_old % 4 != 0:
        comment_padding_old = 4 - block_length_old % 4
    else:
        comment_padding_old = 0

    file_out.write(struct.pack('<L', block_length_new))

    # Copy byte-order magic, and major and minor versions header segment, and Section Length (assumed to be 8 Bytes
    # of FF)
    header = file_in.read(16)
    file_out.write(header)
    remaining_header = block_length_old - 24

    # If correctly formatted comment does not exist, insert comment
    if comment_length_old == 0:
        # Insert option type and un-padded length
        file_out.write(struct.pack('<H', 1))
        file_out.write(struct.pack('<H', comment_length_new))

        # Insert new comment and padding
        file_out.write(bytes(comment, 'utf-8'))
        file_out.write(b'\x00' * comment_padding_new)

        # Get first option type and length and decrement the remaining header byte count
        opt_type = struct.unpack('<H', file_in.read(2))[0]
        opt_length = struct.unpack('<H', file_in.read(2))[0]
        if opt_length % 4 != 0:
            opt_padding = 4 - opt_length % 4
        else:
            opt_padding = 0
        remaining_header -= 4

        # Loop through remaining header to check each option if comment
        while remaining_header > 0 and opt_type != 0:
            # Copy option type
            file_out.write(struct.pack('<H', opt_type))
            # COpy option length
            file_out.write(struct.pack('<H', opt_length))
            # Copy option value
            file_out.write(file_in.read(opt_length))
            remaining_header -= opt_length
            # Copy option padding
            file_out.write(file_in.read(opt_padding))
            remaining_header -= opt_padding

            # Read next option type and length and adjust remaining header
            opt_type = struct.unpack('<H', file_in.read(2))[0]
            opt_length = struct.unpack('<H', file_in.read(2))[0]
            if opt_length % 4 != 0:
                opt_padding = 4 - opt_length % 4
            else:
                opt_padding = 0
            remaining_header -= 4
    # Else: locate comment option, replace it, and copy everything else
    else:
        # Get first option type and length and decrement the remaining header byte count
        opt_type = struct.unpack('<H', file_in.read(2))[0]
        opt_length = struct.unpack('<H', file_in.read(2))[0]
        if opt_length % 4 != 0:
            opt_padding = 4 - opt_length % 4
        else:
            opt_padding = 0
        remaining_header -= 4

        # Loop through remaining header to check each option if comment
        while remaining_header > 0 and opt_type != 0:
            # Process comment (opt_type = 1)
            if opt_type == opt_comment:
                # Read COMMENT
                comment = file_in.read(opt_length).decode('utf-8')
                remaining_header -= opt_length

                # If proper format, Discard old
                if is_json(comment):
                    # TODO: Check if the JSON is the one of interest. If there are more than one json formatted comment,
                    #  and the first on is not the one of interest, then it will be unreachable
                    # mydict = json.loads(comment)

                    # Discard old padding:
                    file_in.read(comment_padding_old)
                    remaining_header -= comment_padding_old

                    # Insert option type and un-padded length
                    file_out.write(struct.pack('<H', 1))
                    file_out.write(struct.pack('<H', comment_length_new))

                    # Insert new comment and padding
                    file_out.write(bytes(comment, 'utf-8'))
                    file_out.write(b'\x00' * comment_padding_new)
                # If not the correct comment, copy into new
                else:
                    # Copy option type
                    file_out.write(struct.pack('<H', opt_type))
                    # Copy option length
                    file_out.write(struct.pack('<H', opt_length))
                    # Copy old comment
                    file_out.write(bytes(comment, 'utf-8'))
                    # Copy comment padding
                    file_out.write(file_in.read(opt_padding))
                    remaining_header -= opt_padding
            else:
                # Copy option type
                file_out.write(struct.pack('<H', opt_type))
                # COpy option length
                file_out.write(struct.pack('<H', opt_length))
                # Copy option value
                file_out.write(file_in.read(opt_length))
                remaining_header -= opt_length
                # Copy option padding
                file_out.write(file_in.read(opt_padding))
                remaining_header -= opt_padding

            # Read next option type and length and adjust remaining header
            opt_type = struct.unpack('<H', file_in.read(2))[0]
            opt_length = struct.unpack('<H', file_in.read(2))[0]
            if opt_length % 4 != 0:
                opt_padding = 4 - opt_length % 4
            else:
                opt_padding = 0
            remaining_header -= 4

    # Write end_of_options
    # Copy option type
    file_out.write(struct.pack('<H', opt_type))
    # COpy option length
    file_out.write(struct.pack('<H', opt_length))

    # Replace BLOCK TOTAL LENGTH (ending)
    file_in.read(4)
    file_out.write(struct.pack('<L', block_length_new))

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
    file_in = '../captures/cap10/ietf-hackathon_pieces_wireshark-commented.pcapng'
    print(extract_comment(file_in, json_only=False))

    insert_comment(file_in, comment_envi, 'testx.pcapng')

    comment_xtrcted = extract_comment('testx.pcapng')

    print(parse_comment(comment_xtrcted))
