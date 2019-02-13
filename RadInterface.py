from __future__ import print_function
from RadState import RadState
from scapy.all import sendp, sniff, wireshark, sr1
import random

class RadInterface:
    '''
    Interface for interacting with Radius server
    '''

    def __init__(self, args):
        sport = random.randint(40000, 65000)
        self.state = RadState(args.r, args.s, args.p, sport, args.u, args.au)

    def query(self, qstring):

        # ACCESS_REQUEST(<username/anon/random>|OTHERSTUFF)
        ar = 'ACCESS_REQUEST'
        if ar in qstring:
            args = qstring[len(ar) + 1:-2].split('|')
            usertype = args[0].lower()
            pac = self.state.access_request(id_=usertype)
            print(pac.show())
            back = sendp(pac, count=1, iface='lo')
            back[0]


