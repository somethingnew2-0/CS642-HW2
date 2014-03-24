#!/usr/bin/env python

import math, optparse, random, sys, time, socket, struct
from collections import deque
import dpkt

# For debugging
import pdb

class IDS(object):
    MAC_ADDRESSES = {
        '\xC0\xA8\x00\x64': '\x7C\xD1\xC3\x94\x9E\xB8', # 192.168.0.100
        '\xC0\xA8\x00\x67': '\xD8\x96\x95\x01\xA5\xC9', # 192.168.0.103
        '\xC0\xA8\x00\x01': '\xF8\x1A\x67\xCD\x57\x6E', # 192.168.0.1
    }

    port_scan = {}
    syn_flood = {}

    def __init__(self):
        usage = '%prog <pcap>'
        self.op = optparse.OptionParser(usage=usage)

    def _format_hw(self, addr):
        return ':'.join(x.encode('hex') for x in addr)

    def _format_ip(self, addr):
        return socket.inet_ntoa(addr)

    def _format_nums(self, pkts):
        return '[%s]' % ','.join(str(pkt['num']) for pkt in pkts)

    def test_arp_spoof(self, arp, num):
        if arp.spa in self.MAC_ADDRESSES and  arp.sha != self.MAC_ADDRESSES[arp.spa]:
            print 'Warning: Arp spoofing detected with invalid address %s for packet number %d' % (self._format_hw(arp.sha), num)

    def test_port_scan_tcp(self, tcp, ip, num):
        if tcp.flags == dpkt.tcp.TH_SYN:
            self.test_port_scan(tcp.dport, ip, num)

    def test_port_scan_udp(self, udp, ip, num):
            self.test_port_scan(udp.dport, ip, num)

    def test_port_scan(self, port, ip, num): 
        if ip.dst in self.port_scan:
            pkts = self.port_scan[ip.dst]            
            for pkt in pkts:    
                if port == pkt['port']:
                    return
            pkts.append({'src': ip.src, 'dst': ip.dst, 'num': num, 'port': port})
        else:
            self.port_scan[ip.dst] = [{'src': ip.src, 'dst': ip.dst, 'num': num, 'port': port}]

    def finish_test_port_scan(self): 
        for dst in self.port_scan:
            pkts = self.port_scan[dst]
            if len(pkts) > 100:
                print 'Warning: Port scan detected from source address %s and victim address %s for packet numbers %s' % (self._format_ip(pkts[0]['src']), self._format_ip(pkts[0]['dst']), self._format_nums(pkts))

    def test_syn_flood(self, tcp, ip, ts, num): 
        if tcp.flags == dpkt.tcp.TH_SYN:
            dst = ip.dst+':'+str(tcp.dport)
            if dst in self.syn_flood:
                pkts = self.syn_flood[dst] 
                while len(pkts) > 0:
                    pkt = pkts[0]
                    if ts - pkt['ts'] >= 1:
                        pkts.popleft()
                    else:
                        break

                pkts.append({'src': ip.src, 'dst': ip.dst, 'num': num, 'port': tcp.dport, 'ts': ts})

                if len(pkts) > 100:
                    print 'Warning: Syn flood detected from source address %s and victim address %s for packet numbers %s' % (self._format_ip(pkts[0]['src']), self._format_ip(pkts[0]['dst']), self._format_nums(pkts))
                    pkts.clear()
            else:
                self.syn_flood[dst] = deque([{'src': ip.src, 'dst': ip.dst, 'num': num, 'port': tcp.dport, 'ts': ts}])

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
            level3 = eth.data
            if type(level3) is dpkt.arp.ARP:
                self.test_arp_spoof(level3, num)
            elif type(level3) is dpkt.ip.IP:
                level4 = level3.data
                if type(level4) is dpkt.tcp.TCP:
                    self.test_port_scan_tcp(level4, level3, num)
                    self.test_syn_flood(level4, level3, ts, num)
                elif type(level4) is dpkt.udp.UDP:
                    self.test_port_scan_udp(level4, level3, num)

        self.finish_test_port_scan()            

        f.close()        

if __name__ == '__main__':
    p = IDS()
    p.main()

