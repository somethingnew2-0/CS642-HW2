#!/usr/bin/env python

import math, optparse, random, sys, time
import dpkt

# For debugging
import pdb

class IDS(object):
    MAC_ADDRESSES = {
        '\xC0\xA8\x00\x64': '\x7C\xD1\xC3\x94\x9E\xB8', # 192.168.0.100
        '\xC0\xA8\x00\x67': '\xD8\x96\x95\x01\xA5\xC9', # 192.168.0.103
        '\xC0\xA8\x00\x01': '\xF8\x1A\x67\xCD\x57\x6E', # 192.168.0.1
    }

    def __init__(self):
        usage = '%prog <pcap>'
        self.op = optparse.OptionParser(usage=usage)

    def test_arp_spoof(self, arp, num):
        if arp.spa in self.MAC_ADDRESSES and  arp.sha != self.MAC_ADDRESSES[arp.spa]:
            print 'Warning: Arp spoofing detected for packet number %d with invalid address %s' % (num, ':'.join(x.encode('hex') for x in arp.sha))
            #pdb.set_trace()

    def main(self, argv=None):
        if not argv:
            argv = sys.argv[1:]
        opts, args = self.op.parse_args(argv)
    
        if not args:
            self.op.error('missing pcap file')
        elif len(args) > 1:
            self.op.error('only one pcap file may be specified')

        f = open(args[0])
        pcap = dpkt.pcap.Reader(f)


        for idx, (ts, buf) in enumerate(pcap):
            num = idx + 1
            eth = dpkt.ethernet.Ethernet(buf)
            if(type(eth.data) is dpkt.arp.ARP):
                self.test_arp_spoof(eth.data, num)
            

        f.close()        

if __name__ == '__main__':
    p = IDS()
    p.main()

