from __future__ import print_function
from hashlib import md5
import hmac
from scapy.all import IP, UDP, Radius, RadiusAttribute, Ether, EAP, EAP_MD5
import os
import random
import string
import struct

class RadState:
    '''
    Object to hold the state of the radius server
    '''

    def __init__(self, hostname, secret, dport, sport, username, anon_username, password):
        self.hostname = hostname
        self.secret = secret
        self.sport = sport
        self.dport = dport
        self.username = username
        self.anon_username = anon_username
        self.password = password
        self.id = random.randint(0, 100) # Packet counter
        self.header_packet = (IP(dst=hostname, id=29)
                              / UDP(sport=sport, dport=dport))
        self.authenticator = os.urandom(16)
        self.sauth = None # Last recived authenticator from server
        self.schallenge = None # Last recived challenge from server
        self.default_attributes = [
            # Shows in the packet trace going to 127.0.1.1
            #RadiusAttribute(type='NAS-IP-Address', value='127.0.1.1'), # machine static ip
            #RadiusAttribute(type='NAS-Port', value='\x00\x00\x00\x00'),
            #RadiusAttribute(
                #type='Message-Authenticator',
                #value=self.authenticator)
        ]
        self.eapid = 1 # EAP counter
        self.state = None # State avp from server

    def access_request(self, kwargs):

        def get(value):
            try:
                return kwargs[value]
            except:
                return 'none'

        atts = []

        # ID AVP
        user = get('USER').lower()

        if 'anon' in user:
            atrib = RadiusAttribute(type='User-Name', value=self.anon_username)
            atts.append(atrib)
        elif 'username' in user:
            atrib = RadiusAttribute(type='User-Name', value=self.username)
            atts.append(atrib)
        elif 'random' in user:
            letters = string.ascii_lowercase
            randuser = ''.join(random.choice(letters) for i in range(10))
            atts.append(RadiusAttribute(type='User-Name', value=randuser))


        # PASSWORD AVP
        passtype = get('PASS').lower()

        if 'password' in passtype:
            atrib = RadiusAttribute(type='User-Password',
                                    value=radcrypt(self.secret,
                                                   self.authenticator,
                                                   self.password))
            atts.append(atrib)
        elif 'incorrect' in passtype:
            atrib = RadiusAttribute(type='User-Password',
                                    value=os.urandom(16))
            atts.append(atrib)

        # EAP AVP
        eap = get('EAP').lower()

        if 'request' in eap:
            atrib = RadiusAttribute(type='EAP-Message',
                                    value=EAP(code='Response',
                                              id=self.eapid,
                                              type='Identity',
                                              identity=atts[0].value))
            atts.append(atrib)
            self.eapid += 1
        if 'md5_response' in eap:
            atrib = RadiusAttribute(
                type='EAP-Message',
                value=EAP_MD5(
                    code='Response',
                    id=self.eapid,
                    type='MD5-Challenge',
                    value=self.md5response()))
            atts.append(atrib)
            self.eapid += 1

        # State

        state = get('STATE').lower()

        print(state)
        if 'correct' in state and self.state:
            atrib = RadiusAttribute(type='State',
                                    value=self.state)
            atts.append(atrib)
        elif 'none' in state:
            ''
        else:
            atrib = RadiusAttribute(type='State',
                                    value=os.urandom(18))
            atts.append(atrib)



        # Message authenticator

        messa = get('MEAU').lower()

        if 'correct' in messa or 'zero' in messa:
            # Placeholder, needs to be calculated
            atrib = RadiusAttribute(type='Message-Authenticator',
                                    value=('\x00' * 16))
            atts.append(atrib)
        if 'incorrect' in messa:
            atrib = RadiusAttribute(type='Message-Authenticator',
                                    value=os.urandom(16))
            atts.append(atrib)


        atts.extend(self.default_attributes)

        packet = Radius(code='Access-Request',
                        authenticator=self.authenticator,
                        id=self.id, attributes=atts)

        # If correct, message_authenticator
        if 'correct' in messa:
            pac = str(packet)
            hash_ = hmac.new(self.secret, pac)
            mess_auth = hash_.digest()
            packet.attributes[-1] = RadiusAttribute(type='Message-Authenticator',
                                                    value=mess_auth)


        self.id = 1 + self.id
        return self.header_packet / packet
    def md5response(self):
        hash_ = md5()
        hash_.update(struct.pack('!B', self.eapid) + self.password + self.schallenge)
        return hash_.digest()


def radcrypt(secret, authenticator, password):
    """Encrypt a password with the secret and authenticator."""
    # First, pad the password to multiple of 16 octets.
    password += b'\0' * (16 - (len(password) % 16))

    if len(password) > 128:
        raise ValueError('Password exceeds maximun of 128 bytes')

    result, last = b'', authenticator
    while password:
        # md5sum the shared secret with the authenticator,
        # after the first iteration, the authenticator is the previous
        # result of our encryption.
        hash_ = md5(secret + last).digest()
        for i in range(16):
            result += chr(ord(hash_[i]) ^ ord(password[i]))
        # The next iteration will act upon the next 16 octets of the password
        # and the result of our xor operation above. We will set last to
        # the last 16 octets of our result (the xor we just completed). And
        # remove the first 16 octets from the password.
        last, password = result[-16:], password[16:]

    return result
