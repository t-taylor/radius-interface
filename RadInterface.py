from __future__ import print_function
from RadState import RadState
from scapy.all import sr1, Radius, ICMP
from scapy.layers.radius import _packet_codes as radius_codes, _radius_attribute_types as attribute_codes
import random

class RadInterface:
    '''
    Interface for interacting with Radius server
    '''

    def __init__(self, args):
        sport = random.randint(40000, 65000)
        self.state = RadState(args.r, args.s, args.p, sport, args.u, args.au)
        self.interface = args.i

    def query(self, qstring):

        # ACCESS_REQUEST(<username/anon/random>|OTHERSTUFF)
        ar = 'RADIUS_ACCESS_REQUEST'
        if ar in qstring:
            args = qstring[len(ar) + 1:-2].split('|')
            usertype = args[0].lower()
            pac = self.state.access_request(id_=usertype)
            print('--------- sending packet')
            print(pac.show())
            back = sr1(pac, iface=self.interface)
            return self.response_parse(back[0])

    def response_parse(self, packet):

        print('--------- recived packet')
        packet.show()
        print('---------')

        try:
            picmp = packet[ICMP]
            if (picmp.type) == 3:
                raise EnvironmentError('RADIUS not reachable')
            return 'ICMP' # Shouldn't happen. If this layer happens to be
                          # important I'll implement it

        except IndexError:
            'no ICMP layer'

        try:
            prad = packet[Radius]
            pstring = 'RADIUS_'
            pstring += radius_codes[prad.code].upper().replace('-', '_')
            pstring += '('

            # Nice little bit of code
            def at_map(attr):
                s = ''
                s += attribute_codes[attr.type].upper().replace('-', '_')
                s += '='
                s += '\'' + attr.value + '\''
                return s

            pstring += '|'.join(map(at_map, prad.attributes))
            pstring += ')'

            return pstring

        except IndexError:
            'no RADIUS layer'

        raise SyntaxError('A packet was unparsed: %s' % packet.summary())


