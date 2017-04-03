import Library.Encriptacion


class Usuario:

    def __init__(self, nick, connection, key_user, key_server, server):
        self.connection = connection
        self.nick = nick
        self.key_user = key_user
        self.key_server = key_server
        self.server = server
        self.busy = False

    def send(self, msj):
        """
        Sends to the user
        :param msj: Message to send
        :return: VOID
        """
        try:
            msj = Library.Encriptacion.encripta(msj, self.key_user).encode()
            self.connection.send(msj)
        except:
            self.server.erase.append(self.nick)
            return False

    def recv(self, limite=1024*1024):
        """
        Receive from user
        :param limite: Size of data to be received
        :return: Data received
        """
        try:
            msj = self.connection.recv(limite).decode()
            msj = Library.Encriptacion.desencripta(msj, self.key_server)
            return msj
        except:
            return False

    def is_online(self):
        pass
