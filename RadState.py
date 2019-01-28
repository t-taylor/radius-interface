class RadState:
    '''
    Object to hold the state of the radius server
    '''

    def __init__(self, hostname, port, secret):
        self.hostname = hostname
        self.port = port
        self.secret = secret
