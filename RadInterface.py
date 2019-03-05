from __future__ import print_function
from RadState import RadState
from scapy.all import sr1, Radius, ICMP, EAP
from scapy.layers.radius import _packet_codes as radius_codes, _radius_attribute_types as attribute_codes
from scapy.layers.eap import eap_types

import random

class RadInterface:
    '''
    Interface for interacting with Radius server
    '''

    def __init__(self, args, verbose):
        sport = random.randint(40000, 65000)
        self.state = RadState(args.r, args.s, args.P, sport, args.u, args.au, args.p)
        self.interface = args.i
        self.verbose = verbose

    def query(self, qstring):

        # ACCESS_REQUEST(USER=<username/anon/random>|PASS=<password/none>|ID=<id number>|EAP=<requeset/none>)
        ar = 'RADIUS_ACCESS_REQUEST'
        if ar in qstring:
            args = qstring[len(ar) + 1:-2].split('|')

            options = dict()
            for arg in args:
                if len(arg) != 0:
                    vk = arg.split('=')
                    options[vk[0]] = vk[1]

            pac = self.state.access_request(options)

            if self.verbose:
                for k,v in options.items():
                    print('k: %s, v: %s' % (k, v))
                print('--------- sending packet')
                print(pac.show())

            back = sr1(pac, iface=self.interface, verbose=self.verbose)
            return self.response_parse(back[0])


    def response_parse(self, packet):

        if self.verbose:
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
                if 'MESSAGE_AUTHENTICATOR' in s:
                    s += '' # Dont show string
                elif 'STATE' in s:
                    s += '' # Dont show string
                    self.state.state = attr.value
                elif 'EAP_MESSAGE' in s:
                    peap = attr.value
                    s += '='
                    if peap.code == 4:
                        s += 'EAP_FAILURE'
                    elif peap.code == 3:
                        s += 'EAP_SUCCESS'
                    elif 'MD5-Challenge' in eap_types[peap.type]:
                        self.state.schallenge = peap.value
                        s += 'MD5_CHALLENGE'
                    else:
                        s += peap.summary()
                else:
                    s += '='
                    s += '\'' + str(attr.value) + '\''
                return s

            pstring += '|'.join(map(at_map, prad.attributes))
            pstring += ')'

            self.state.sauth = prad.authenticator

            return pstring

        except IndexError:
            'no RADIUS layer'

        raise SyntaxError('A packet was unparsed: %s' % packet.summary())


