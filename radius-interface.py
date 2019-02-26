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
    parser.add_argument('-r', help='radius server ip', required=True)
    parser.add_argument('-p', help='password', required=True)
    parser.add_argument('-P', help='port number', default=1812)
    parser.add_argument('-f', help='File name for optional query file')
    parser.add_argument('-i', help='Interface name', required=True)
    parser.add_argument('-v', help='verbose/debug', default=False)
    args = parser.parse_args(argv[1:])

    ri = RadInterface(args, args.v)

    ln = 0
    with open(args.f) as f:
        for line in f:
            print(('%s: ' % ln) + line)
            result = ri.query(line)
            print(('%s: ' % ln) + result)



if __name__ == '__main__':
    main()
