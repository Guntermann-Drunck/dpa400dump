#!/usr/bin/env python2

# Copyright 2018, Dirk Eibach, Guntermann & Drunck GmbH <dirk.eibach@gdsys.cc>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

"""
Unigraf DPA-400 DisplayPort AUX channel monitor extcap

@note
{
To use this script on Windows, please generate an extcap_example.bat inside
the extcap folder, with the following content:

-------
@echo off
<Path to python interpreter> <Path to script file> %*
-------

Windows is not able to execute Python scripts directly, which also goes for all
other script-based formates beside VBScript
}

"""

from __future__ import print_function

import os
import sys
import signal
import re
import argparse
import time
import struct
import binascii
from threading import Thread
import serial
import binascii

ERROR_USAGE          = 0
ERROR_ARG            = 1
ERROR_INTERFACE      = 2
ERROR_FIFO           = 3
ERROR_SERPORT        = 4

CTRL_CMD_INITIALIZED = 0
CTRL_CMD_SET         = 1
CTRL_CMD_ADD         = 2
CTRL_CMD_REMOVE      = 3
CTRL_CMD_ENABLE      = 4
CTRL_CMD_DISABLE     = 5
CTRL_CMD_STATUSBAR   = 6
CTRL_CMD_INFORMATION = 7
CTRL_CMD_WARNING     = 8
CTRL_CMD_ERROR       = 9

CTRL_ARG_LOGGER      = 0

initialized = False

logfile = sys.stdout

"""
This code has been taken from http://stackoverflow.com/questions/5943249/python-argparse-and-controlling-overriding-the-exit-status-code - originally developed by Rob Cowie http://stackoverflow.com/users/46690/rob-cowie
"""
class ArgumentParser(argparse.ArgumentParser):
    def _get_action_from_name(self, name):
        """Given a name, get the Action instance registered with this parser.
        If only it were made available in the ArgumentError object. It is
        passed as it's first arg...
        """
        container = self._actions
        if name is None:
            return None
        for action in container:
            if '/'.join(action.option_strings) == name:
                return action
            elif action.metavar == name:
                return action
            elif action.dest == name:
                return action

    def error(self, message):
        exc = sys.exc_info()[1]
        if exc:
            exc.argument = self._get_action_from_name(exc.argument_name)
            raise exc
        super(ArgumentParser, self).error(message)

#### EXTCAP FUNCTIONALITY

"""@brief Extcap configuration
This method prints the extcap configuration, which will be picked up by the
interface in Wireshark to present a interface specific configuration for
this extcap plugin
"""
def extcap_config(interface, option):
    args = []
    values = []

    args.append ( (0, '--serport', 'Serial Port', 'Serial Port where the DPA-400 is connected', 'string', '{required=true}') )

    if ( len(option) <= 0 ):
        for arg in args:
            print ("arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s" % arg)

def extcap_version():
    print ("extcap {version=1.0}{help=http://www.wireshark.org}{display=DPA400 interface}")

def extcap_interfaces():
    print ("extcap {version=1.0}{help=http://www.wireshark.org}{display=DPA400 interface}")
    print ("interface {value=dpa1}{display=DPA400 interface}")
#    print ("control {number=%d}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}" % CTRL_ARG_LOGGER)

def extcap_dlts(interface):
    if ( interface == '1' ):
        print ("dlt {number=275}{name=DPAUX}{display=DisplayPort AUX channel}")

def validate_capture_filter(capture_filter):
    if capture_filter != "filter" and capture_filter != "valid":
        print("Illegal capture filter")

fn_out = None

def control_read(fn):
    try:
        header = fn.read(6)
        sp, _, length, arg, typ = struct.unpack('>sBHBB', header)
        if length > 2:
            payload = fn.read(length - 2)
        else:
            payload = ''
        return arg, typ, payload
    except:
        return None, None, None

def control_read_thread(control_in):
    global initialized, fn_out, message, delay, verify, button, button_disabled
    with open(control_in, 'rb', 0 ) as fn:
        arg = 0
        while arg != None:
            arg, typ, payload = control_read(fn)
            log = ''
            if typ == CTRL_CMD_INITIALIZED:
                initialized = True

def control_write(arg, typ, payload):
    global fn_out
    packet = bytearray()
    packet += struct.pack('>sBHBB', b'T', 0, len(payload) + 2, arg, typ)
    if sys.version_info[0] >= 3 and isinstance(payload, str):
        packet += payload.encode('utf-8')
    else:
        packet += payload
    fn_out.write(packet)

def unsigned(n):
    return int(n) & 0xFFFFFFFF

def pcap_header_get():
    header = bytearray()
    header += struct.pack('<L', int ('a1b2c3d4', 16 ))
    header += struct.pack('<H', unsigned(2) ) # Pcap Major Version
    header += struct.pack('<H', unsigned(4) ) # Pcap Minor Version
    header += struct.pack('<I', int(0)) # Timezone
    header += struct.pack('<I', int(0)) # Accurancy of timestamps
    header += struct.pack('<L', int ('0000ffff', 16 )) # Max Length of capture frame
    header += struct.pack('<L', unsigned(275)) # DPAUX
    return header

def pcap_pack(data):
    pcap = bytearray()

    caplength = len(data)
    timestamp = int(time.time())

    pcap += struct.pack('<L', unsigned(timestamp ) ) # timestamp seconds
    pcap += struct.pack('<L', 0x00  ) # timestamp nanoseconds
    pcap += struct.pack('<L', unsigned(caplength ) ) # length captured
    pcap += struct.pack('<L', unsigned(caplength ) ) # length in frame

    pcap += data

    print(binascii.hexlify(pcap), file=logfile)

    return pcap

txctr = 0x00
cfg_monitor = 0x03
cfg_start_on = 0x00
cfg_stop_on = 0x00

def dpa_send(serport, data):
    global txctr

    packet = bytearray()

    packet += struct.pack('2s', "UG" ) # Unigraf packet start magic
    packet += struct.pack('H', unsigned(len(data))) # Packet length
    packet += struct.pack('B', txctr & 0xff) # Packet counter
    packet += struct.pack('B', sum(packet) & 0xff) # Header checksum
    packet += data
    packet += struct.pack('2s', "GU" )  # Unigraf packet end magic

    # print(binascii.hexlify(packet), file=logfile)

    serport.write(packet)

    txctr += 1

def dpa_get_reply(serport):

    try:
        magic, plen, ctr_a, ctr_b = struct.unpack('2sHBB', serport.read(6))
    except struct.error:
        return None

    if (magic != "UG"):
        return None

    reply = serport.read(plen)

    magic = serport.read(2)
    if (magic != "GU"):
        return None
    # print(binascii.hexlify(reply), file=logfile)

    return reply

def dpa_get_fw_ver(serport):
    packet = bytearray([0x19])

    dpa_send(serport, packet)
    cmd, v0, v1, v2 = struct.unpack('BBBB', dpa_get_reply(serport))

    return "{}.{}.{}".format(v0, v1, v2)

def dpa_get_fpga_ver(serport):
    packet = bytearray([0x1a])

    dpa_send(serport, packet)
    cmd, v0, v1, v2 = struct.unpack('BBBB', dpa_get_reply(serport))

    return "{}.{}.{}".format(v0, v1, v2)

def dpa_start(serport):
    sequence = [bytearray([0x18]), bytearray([0x11]), bytearray([0x14, cfg_monitor]), bytearray([0x15, cfg_start_on]), bytearray([0x16, cfg_stop_on]), bytearray([0x17])]

    for packet in sequence:
        dpa_send(serport, packet)
        reply = dpa_get_reply(serport)
        if reply is None:
            return None

    return reply

def dpa_stop(serport):
    packet = bytearray([0x18])

    dpa_send(serport, packet)

    return dpa_get_reply(serport)

def dpa_poll(serport):
    packet = bytearray([0x12, 0x00, 0x10])

    dpa_send(serport, packet)

    return dpa_get_reply(serport)

class StreamHandler:

    def reset(self):
        self._remainder = bytearray()

    def __init__(self, fh):
        self.fh = fh
        self.reset()

    def _get_packet(self, string):
        data = bytearray(string)
        cmd = data[0]
        packet = bytearray([cmd])

        print("dpa_get_packet(" + binascii.hexlify(data) + ")", file=logfile)

        if data[1] != 0x01:
            print("Malformed: {} instead of 0x01".format(data[1]), file=logfile)
            sys.exit(1)

        if cmd == 0x84:
            return 2, packet
        elif cmd in [0x02, 0x03]:
            packet.append(data[8])
            return 10, packet
        elif cmd == 0x04:
            return 8, packet
        elif cmd == 0x00:
            packet.append(not(data[6] & 0x80)) # from_source
            i = 8
            while (i < len(data)):
                if data[i + 1]:
                    return i + 2, packet
                packet.append(data[i])
                i += 2
            return 0, None
        else:
            return 0, None

    def put(self, data):
        cmd, len_a, start, len_b = struct.unpack('>BHHH', data[0:7])
        self._remainder += data[7:]
        i = 0

        while len(self._remainder[i:]):
            consumed, packet = self._get_packet(self._remainder[i:])
            if not packet:
                print("None", file=logfile)
                break
            else:
                print("got " + binascii.hexlify(packet), file=logfile)
            self.fh.write(pcap_pack(packet))
            i += consumed

        self._remainder = self._remainder[i:]

def extcap_capture(interface, fifo, control_in, control_out, serport):
    global fn_out

    with open(fifo, 'wb', 0 ) as fh:
        fh.write (pcap_header_get())

        if control_out != None:
            fn_out = open(control_out, 'wb', 0)
            control_write(CTRL_ARG_LOGGER, CTRL_CMD_SET, "Log started at " + time.strftime("%c") + "\n")

        if control_in != None:
            # Start reading thread
            thread = Thread(target = control_read_thread, args = (control_in))
            thread.start()

        sh = StreamHandler(fh)

        while True:
            data = dpa_poll(serport)
            if data:
                sh.put(data)

def extcap_close_fifo(fifo):
    # This is apparently needed to workaround an issue on Windows/macOS
    # where the message cannot be read. (really?)
    fh = open(fifo, 'wb', 0 )
    fh.close()

####

def usage():
    print ( "Usage: %s <--extcap-interfaces | --extcap-dlts | --extcap-interface | --extcap-config | --capture | --extcap-capture-filter | --fifo | --logfile>" % sys.argv[0] )

if __name__ == '__main__':
    global pcaplog
    interface = ""
    option = ""

    # change this to get a logfile
    logfile = open(os.devnull, 'w')

    # Capture options
    delay = 0
    message = ""
    fake_ip = ""
    ts = 0

    parser = ArgumentParser(
            prog="Extcap DPA400 DisplayPort AUX channel monitor",
            description="Extcap DPA400 DisplayPort AUX channel monitor for python"
            )

    # Extcap Arguments
    parser.add_argument("--capture", help="Start the capture routine", action="store_true" )
    parser.add_argument("--extcap-interfaces", help="Provide a list of interfaces to capture from", action="store_true")
    parser.add_argument("--extcap-interface", help="Provide the interface to capture from")
    parser.add_argument("--extcap-dlts", help="Provide a list of dlts for the given interface", action="store_true")
    parser.add_argument("--extcap-config", help="Provide a list of configurations for the given interface", action="store_true")
    parser.add_argument("--extcap-capture-filter", help="Used together with capture to provide a capture filter")
    parser.add_argument("--fifo", help="Use together with capture to provide the fifo to dump data to")
    parser.add_argument("--extcap-control-in", help="Used to get control messages from toolbar")
    parser.add_argument("--extcap-control-out", help="Used to send control messages to toolbar")
    parser.add_argument("--extcap-version", help="Shows the version of this utility", nargs='?', default="")
    parser.add_argument("--extcap-reload-option", help="Reload elements for the given option")

    # Interface Arguments
    parser.add_argument("--serport", help="Serial Port", nargs='?', default="" )
    parser.add_argument("--logfile", help="Logfile", nargs='?', default="" )

    try:
        args, unknown = parser.parse_known_args()
    except argparse.ArgumentError as exc:
        print( "%s: %s" % ( exc.argument.dest, exc.message ), file=logfile)
        fifo_found = 0
        fifo = ""
        for arg in sys.argv:
            if (arg == "--fifo" or arg == "--extcap-fifo") :
                fifo_found = 1
            elif ( fifo_found == 1 ):
                fifo = arg
                break
        extcap_close_fifo(fifo)
        sys.exit(ERROR_ARG)

    if ( len(sys.argv) <= 1 ):
        parser.exit("No arguments given!")

    if args.logfile:
        logfile.close()
        logfile = open(args.logfile, 'w')

    if ( args.extcap_version and not args.extcap_interfaces ):
        extcap_version()
        sys.exit(0)

    if ( args.extcap_interfaces == False and args.extcap_interface == None ):
        parser.exit("An interface must be provided or the selection must be displayed")
    if ( args.extcap_capture_filter and not args.capture ):
        validate_capture_filter(args.extcap_capture_filter)
        sys.exit(0)

    if ( args.extcap_interfaces == True or args.extcap_interface == None ):
        extcap_interfaces()
        sys.exit(0)

    if ( len(unknown) > 1 ):
        print("dpa400 %d unknown arguments given" % len(unknown), file=logfile )

    m = re.match ( 'dpa(\d+)', args.extcap_interface )
    if not m:
        sys.exit(ERROR_INTERFACE)
    interface = m.group(1)

    if ( args.extcap_reload_option and len(args.extcap_reload_option) > 0 ):
        option = args.extcap_reload_option

    if args.extcap_config:
        extcap_config(interface, option)
    elif args.extcap_dlts:
        extcap_dlts(interface)
    elif args.capture:
        if args.fifo is None:
            sys.exit(ERROR_FIFO)
        if args.serport is None:
            sys.exit(ERROR_SERPORT)

        try:
            serport = serial.Serial(args.serport, 115200, timeout=1)
            print("Firmware version " + dpa_get_fw_ver(serport), file=logfile)
            print("FPGA version " + dpa_get_fpga_ver(serport), file=logfile)
        except serial.SerialException:
            print("Could not open serial port %s" % args.serport, file=sys.stderr)
            extcap_close_fifo(args.fifo)
            sys.exit(ERROR_SERPORT)

        if dpa_start(serport) is None:
            print("Could not establish communication to DPA400", file=sys.stderr)
            extcap_close_fifo(args.fifo)
            sys.exit(ERROR_SERPORT)


        try:
            extcap_capture(interface, args.fifo, args.extcap_control_in, args.extcap_control_out, serport)
        except KeyboardInterrupt:
            pass

        dpa_stop(serport)
        serport.close()
    else:
        usage()
        sys.exit(ERROR_USAGE)
