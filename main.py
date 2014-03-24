#!/usr/bin/env python

import math, optparse, random, socket, sys, time
import dpkt

class IDS(object):
    def __init__(self):
        usage = '%prog <pcap>'
        self.op = optparse.OptionParser(usage=usage)

    def gen_ping(self, opts):
        pass
    def open_sock(self, opts):
        pass
    def print_header(self, opts):
        pass
    def print_reply(self, opts, buf):
        pass
    
    def main(self, argv=None):
        if not argv:
            argv = sys.argv[1:]
        opts, args = self.op.parse_args(argv)
    
        if not args:
            self.op.error('missing pcap file')
        elif len(args) > 1:
            self.op.error('only one pcap file may be specified')

        pcap = args[0]

if __name__ == '__main__':
    p = IDS()
    p.main()

