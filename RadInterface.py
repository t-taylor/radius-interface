from radius import Radius as Rad

rad = Rad('shush', host='localhost', port=1812)
print( rad.authenticate('tom', 'ttyInput99\!') )

class RadInterface:
    '''
    Interface for interacting with Radius server
    '''

    def __init__(self, hostname, port, secret):
        self.state = RadState(hostname, port, secret)
