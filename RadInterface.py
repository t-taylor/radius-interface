from __future__ import print_function
from RadState import RadState
import random

class RadInterface:
    '''
    Interface for interacting with Radius server
    '''

    def __init__(self, hostname, dport, secret):
        self.sport = random.randint(40000, 65000)
        self.dport = dport
        self.state = RadState(hostname, secret, dport, sport)

    def query(self, qstring):

        # ACCESS_REQUEST(<username/anon/random>|OTHERSTUFF)
        ar = 'ACCESS_REQUEST'
        if ar in qstring:
            args = qstring[len(ar) + 1:-1].split('|')
            usertype = args[0].lower()
            if 'username' in usertype:
                'send actual username'
            elif 'anon' in usertype:
                'send anon id'
            elif 'random' in usertype:
                'send random string'


