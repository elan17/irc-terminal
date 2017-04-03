import socket
import multiprocessing
import Library.Usuario
import Library.Encriptacion
import Library.interfaz


class Server:

    def __init__(self, salir, handler, keys, ip="localhost", port=8000):
        """
        Builder for the class

        :param salir: Multiproccesing.Manager.Value(boolean) object. True to exit program
        :param handler: Class that will receive messages and exceptions
        :param ip: Ip for the server
        :param port: Port for the server
        :return VOID
        """
        self.handler = handler
        self.claves = keys
        self.ip = ip
        self.port = port
        m = multiprocessing.Manager()
        self.connections = self.handler.connections
        self.erase = m.list()
        self.salir = salir

    def server_handler(self):
        """

        Function that setups the server

        :return: VOID
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.handler.pantalla("SOCKET_CREATED")
        try:
            s.bind((self.ip, self.port))
            self.handler.pantalla("SOCKET_BINDED", (self.ip, self.port))
        except socket.error as msg:
            self.handler.pantalla("SOCKET_FAILED", (msg, ))
            self.salir.value = True
            s.close()
            import sys
            sys.exit()
        s.listen(5)
        s.settimeout(0.1)
        self.handler.pantalla("SOCKET_LISTENING")
        while not self.salir.value:
            try:
                conn, addr = s.accept()
                try:
                    self.login(conn)
                except Exception as e:
                    self.handler.pantalla("FAILED_LOGIN", args=(conn.getpeername()[0], repr(e)))
            except socket.timeout:
                pass
        self.handler.pantalla("ENDING_LISTENING")
        s.close()

    def login(self, conn):
        """
        Protocol to log the client on

        :param conn: Connection to log in
        :return: VOID
        """
        conn.send(self.claves[0].encode())
        msg = conn.recv(1024*1024).decode()
        msg = Library.Encriptacion.desencripta(msg, self.claves[1])
        args = msg.split("··")
        user = Library.Usuario.Usuario(args[0], conn, args[1], self.claves[1], self)
        banned = self.handler.get_banned()
        if args[0] in self.connections:
            user.send("NICK_TAKEN")
            conn.close()
        elif conn.getpeername()[0] in banned.values():
            user.send("IP_BANNED")
            conn.close()
        elif args[0] in banned:
            user.send("NICK_BANNED")
            conn.close()
        elif " " in args[0] or len(args) > 2:
            user.send("INVALID_NICK")
            conn.close()
        else:
            self.handler.send_to_all("CONNECTED_USER··" + args[0])
            self.connections[args[0]] = user
            self.handler.pantalla("LOGIN", (args[0], len(self.connections.keys())))
            user.send("OK")

    def listen(self):
        """

        Method which listen to a set of connections,
        controlling if the other end of the pipe is up and calling a function if receives a message

        :return: VOID
        """
        while not self.salir.value:
            self.clear_dict()
            claves = self.connections.keys()
            self.erase = []
            for clave in claves:
                x = self.connections[clave]
                x.connection.settimeout(1)
                try:
                    msg = Library.Encriptacion.desencripta(x.connection.recv(1024*1024).decode(), self.claves[1])
                except socket.error as e:
                    if e.args[0] == "timed out":
                        pass
                    else:
                        self.handler.pantalla("", (e, ))
                        self.delete_client(clave)
                except AssertionError:
                    self.delete_client(clave)
                else:
                    if msg == "":
                        self.delete_client(clave)
                    else:
                        try:
                            self.handler.recv(msg, x)
                        except Exception as e:
                            self.handler.pantalla("REQUEST_FAILED", args=(msg, clave, repr(e)))
        self.erase = self.connections.keys()
        self.clear_dict()

    def clear_dict(self):
        """
        Refreshes the dict, disconnecting clients
        :return: VOID
        """
        for x in self.erase:
            user = self.connections[x]
            try:
                user.connection.shutdown(1)
            except:
                user.connection.close()
            self.connections.pop(x)

    def delete_client(self, clave, notify=True):
        """
        Deletes the given username and prints a message on terminal
        :param clave: Nick of the user to delete
        :param notify: Shall I notify the disconnection of the user?
        :return: VOID
        """
        self.erase.append(clave)
        if notify:
            self.handler.pantalla("DISCONNECTED_USER", (clave, ))
            self.handler.send_to_all("DISCONNECTED_USER··" + clave)
