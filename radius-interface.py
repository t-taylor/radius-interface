#! /usr/bin/env python

from argparse import ArgumentParser as AP
from sys import argv

def main():
    parser = AP()
    parser.add_argument('-f', help='File name for optional query file')
    parser.add_argument('-s', help='Radius Server secret')
    parser.add_argument('-h', help='Hostname', default='localhost')
    parser.add_argument('-p', help='port number', default='1812')
    args = parser.parse_args(argv)

    ri = RadInterface(args.h, args.p, args.s)

    try:
        with open(args.f) as f:
            for line in f:

    except:
        'open socket'



if __name__ == '__main__':
    main()
