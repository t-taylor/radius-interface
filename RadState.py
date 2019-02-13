from __future__ import print_function
from hashlib import md5
from scapy.all import IP, UDP, Radius, RadiusAttribute, Ether
import os
import random
import string

class RadState:
    '''
    Object to hold the state of the radius server
    '''

    def __init__(self, hostname, secret, dport, sport, username, anon_username):
        self.hostname = hostname
        self.secret = secret
        self.sport = sport
        self.dport = dport
        self.username = username
        self.anon_username = anon_username
        self.id = random.randint(0, 100) # Packet counter
        self.header_packet = (Ether(dst = '00:00:00:00:00:00')
                              / IP(dst=hostname, id=29)
                              / UDP(sport=sport, dport=dport))
        self.authenticator = os.urandom(16)
        self.default_attributes = [
            # Shows in the packet trace going to 127.0.1.1
            RadiusAttribute(type='NAS-IP-Address', value='127.0.1.1'), # machine static ip
            RadiusAttribute(type='NAS-Port', value='\x00\x00\x00\x00'),
            #RadiusAttribute(
                #type='Message-Authenticator',
                #value=self.authenticator)
        ]

    def access_request(self, **kwargs):
        atts = []
        user = kwargs['id_']

        if 'anon' in user:
            atrib = RadiusAttribute(type='User-Name', value=self.anon_username)
            atrib.len = len(atrib)
            atts.append(atrib)
        elif 'username' in user:
            atrib = RadiusAttribute(type='User-Name', value=self.username)
            atrib.len = len(atrib)
            atts.append(atrib)
        elif 'random' in user:
            letters = string.ascii_lowercase
            randuser = ''.join(random.choice(letters) for i in range(10))
            atts.append(RadiusAttribute(type='User-Name', value=randuser, len=len(randuser)))

        atts.extend(self.default_attributes)

        packet = Radius(code='Access-Request',
                        authenticator=self.authenticator,
                        id=self.id, attributes=atts)
        self.id = 1 + self.id
        return lenfix(self.header_packet / packet)

def lenfix(packet):
    packet[IP].len = len(packet[IP])
    packet[UDP].len = len(packet[UDP])
    packet[Radius].len = len(packet[Radius])
    return packet


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
        hash = md5(secret + last).digest()
        for i in range(16):
            result += chr(ord(hash[i]) ^ ord(password[i]))
        # The next iteration will act upon the next 16 octets of the password
        # and the result of our xor operation above. We will set last to
        # the last 16 octets of our result (the xor we just completed). And
        # remove the first 16 octets from the password.
        last, password = result[-16:], password[16:]

    return result
