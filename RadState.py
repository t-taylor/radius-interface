from __future__ import print_function
from hashlib import md5
from scapy.all import IP, UDP, Radius, RadiusAttribute

class RadState:
    '''
    Object to hold the state of the radius server
    '''

    def __init__(self, hostname, secret, dport, sport):
        self.hostname = hostname
        self.port = port
        self.secret = secret
        self.header_packet = (IP(dst=hostname)
                              / UDP(sport=randint()))

    def accessrequest(self, **kwargs):
        packet = Radius(code='Access-Request', id=['id'])


# from py-radius
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
