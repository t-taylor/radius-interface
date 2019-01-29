#! /usr/bin/env python

from __future__ import print_function
from argparse import ArgumentParser as AP
from RadInterface import RadInterface
from sys import argv

def main():
    parser = AP()
    parser.add_argument('-f', help='File name for optional query file')
    parser.add_argument('-s', help='Radius Server secret')
    parser.add_argument('-r', help='radius server ip', default='127.0.0.1')
    parser.add_argument('-p', help='port number', default='1812')
    parser.add_argument('-u', help='username')
    parser.add_argument('-au', help='anonymous username')
    args = parser.parse_args(argv[1:])

    ri = RadInterface(args.r, args.p, args.s)

    try:
        with open(args.f) as f:
            for line in f:
                print(line)
                result = ri.query(line)
                print(result)
    except:
        'open socket'



if __name__ == '__main__':
    main()
