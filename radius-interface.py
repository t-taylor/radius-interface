#! /usr/bin/env python

from __future__ import print_function
from argparse import ArgumentParser as AP
from RadInterface import RadInterface
import scapy.all as sc
from sys import argv

def main():
    parser = AP()
    parser.add_argument('-u', help='username', required=True)
    parser.add_argument('-au', help='anonymous username')
    parser.add_argument('-s', help='Radius Server secret', required=True)
    parser.add_argument('-r', help='radius server ip', default='127.0.0.1')
    parser.add_argument('-p', help='port number', default=1812)
    parser.add_argument('-f', help='File name for optional query file')
    parser.add_argument('-i', help='Interface name', required=True)
    args = parser.parse_args(argv[1:])

    # Weird scapy stuff
    # https://stackoverflow.com/questions/4245810/icmp-ping-packet-is-not-generating-a-reply-when-using-scapy
    #if args.r == '127.0.0.1' or args.r == 'localhost':
    #sc.conf.L3Socket = sc.L3RawSocket

    ri = RadInterface(args)

    ln = 0
    with open(args.f) as f:
        for line in f:
            print(('%s: ' % ln) + line)
            result = ri.query(line)
            print(('%s: ' % ln) + result)



if __name__ == '__main__':
    main()
