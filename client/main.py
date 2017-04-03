import Library.interfaz
import Library.Encriptacion
import Library.config
import multiprocessing
import socket


class Client:

    def __init__(self, ip, port, interfaz, bits=1024):
        """

        :param ip: IP where we are connecting
        :param port: Port where we are connecting
        :param interfaz: Interfaz object to handle interface
        """
        self.ip = ip
        self.port = port
        self.interfaz = interfaz
        self.salir = multiprocessing.Manager().Value(bool, False)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.claves = Library.Encriptacion.genera(bits=bits)
        print(self.interfaz.get_str("GET_NICK"))
        self.nick = input("")
        if "··" in self.nick:
            raise ValueError(self.interfaz.get_str("INVALID_NICK"))
        self.s.connect((self.ip, self.port))
        self.publ = self.s.recv(1024 * 1024).decode()
        self.send(self.nick + "··" + self.claves[0])
        returneo = self.recv()
        if returneo == "OK":
            pass
        elif returneo == "NICK_BANNED":
            raise ValueError(self.interfaz.get_str("NICK_BANNED"))
        elif returneo == "IP_BANNED":
            raise Exception(self.interfaz.get_str("IP_BANNED"))
        elif returneo == "INVALID_NICK":
            raise ValueError(self.interfaz.get_str("INVALID_NICK"))
        else:
            raise ValueError(self.interfaz.get_str("NICK_TAKEN"))
        self.pantalla("")

    def run(self):
        """
        Listen to user input
        :return: VOID
        """
        while not self.salir.value:
            msg = input("")
            try:
                self.commands(msg)
            except Exception as e:
                self.pantalla("FAILED_COMMAND", args=(msg, repr(e)))

    def listen(self):
        """
        Listen to server messages
        :return: VOID
        """
        self.s.settimeout(1)
        while not self.salir.value:
            try:
                msg = self.recv()
            except socket.error as e:
                if e.args[0] == "timed out":
                    pass
                else:
                    self.pantalla("FAILED_RECEIVE", args=(repr(e), ))
                    self.salir.value = True
            except AssertionError as e:
                self.pantalla("FAILED_CRYPT", args=(repr(e), ))
                self.salir.value = True
            else:
                if msg == "":
                    self.salir.value = True
                else:
                    try:
                        self.interpreter(msg)
                    except Exception as e:
                        self.pantalla("UNHANDLED_CONNECTION_EXCEPTION", args=(msg, repr(e)))
        self.pantalla("DISCONNECTED")
        self.s.close()

    def interpreter(self, msg):
        """
        Interprets the messages sent by the server
        :param msg: Message from server
        :return: VOID
        """
        command = msg.split("··")
        if command[0] == "say":
            content = msg.replace(command[0]+"··"+command[1]+"··", "")
            self.pantalla("SAY", args=(command[1], content))
        elif command[0] == "DISCONNECTED_USER":
            self.pantalla("DISCONNECTED_USER", args=(command[1], ))
        elif command[0] == "CONNECTED_USER":
            self.pantalla("CONNECTED_USER", args=(command[1], ))
        elif command[0] == "ip":
            self.pantalla("IP_USER", args=(command[1], command[2]))
        elif command[0] == "USER_NOT_FOUND":
            self.pantalla("USER_NOT_FOUND", args=(command[1], ))
        elif command[0] == "IP_GETTING_DISABLE":
            self.pantalla("IP_GETTING_DISABLE")
        elif command[0] == "whisper":
            content = msg.replace(command[0]+"··"+command[1]+"··", "")
            self.pantalla("WHISPER", args=(command[1], content))
        elif command[0] == "userlist":
            self.pantalla("USERLIST", args=(msg.replace(command[0]+"··", ""), ))
        elif command[0] == "KICK":
            self.pantalla("KICK")
            self.salir.value = True
        elif command[0] == "BAN":
            self.pantalla("BAN")
            self.salir.value = True
        elif command[0] == "UNBANNED":
            self.pantalla("UNBANNED", args=(command[1], ))
        else:
            self.pantalla("PROTOCOL_FAILED", args=(msg, ))

    def commands(self, msg):
        """
        Interprets commands inserted by the user
        :param msg: Command to handle
        :return: VOID
        """
        command = msg.split(" ")
        if command[0] == self.interfaz.get_str("EXIT"):
            self.salir.value = True
        elif command[0] == self.interfaz.get_str("SAY_WORD"):
            content = msg.replace(command[0] + " ", "")
            self.send("say··" + content)
        elif command[0] == self.interfaz.get_str("WHISPER_WORD"):
            content = msg.replace(command[0] + " " + command[1], "")
            self.send("whisper··" + command[1] + "··" + content)
        elif command[0] == self.interfaz.get_str("GET_IP"):
            self.send("getip··" + command[1])
        elif command[0] == self.interfaz.get_str("USERLIST_WORD"):
            self.send("userlist")
        elif command[0] == self.interfaz.get_str("HELP"):
            ayuda = self.interfaz.help()
            if ayuda:
                print("\033c")
                print(ayuda)
                self.interfaz.terminal_locked.value = True
                input("")
                self.interfaz.terminal_locked.value = False
                self.interfaz.printear(self.salir)
            else:
                self.pantalla("HELP_FILE_NOT_FOUND")
        else:
            self.pantalla("COMMAND_NOT_FOUND", args=(msg, ))

    def send(self, msg):
        """
        Sends message to server
        :param msg: Message to send
        :return: VOID
        """
        try:
            self.s.send(Library.Encriptacion.encripta(msg, self.publ).encode())
        except Exception as e:
            self.pantalla("FAILED_SEND", args=(msg, repr(e)))

    def recv(self, maxim=1024*1024):
        """
        Receive message from server
        :param maxim: Maximum amount of data to receive
        :return: Message received
        """
        msg = Library.Encriptacion.desencripta(self.s.recv(maxim).decode(), self.claves[1])
        return msg

    def pantalla(self, msg, args=(), prompt=True):
        """

        Handles the output to the console

        :param msg: Key string to search in the Strings file
        :param args: Args to format into the string
        :param prompt: Shall I print the prompt string at the end of the log?
        :return: VOID
        """
        msg = self.interfaz.get_str(msg)
        if msg:
            msg = msg.format(*args)
            self.interfaz.add_log(msg)
        self.interfaz.printear(self.salir, prompt=prompt)


try:
    config = Library.config.read()
except:
    import sys
    print("FAILED TO OPEN CONFIG FILE, EXITING")
    sys.exit()
salir = False
while not salir:
    try:
        client = Client(config["host"], int(config["port"]), Library.interfaz.Interfaz(lang=config["lang"]),
                        bits=int(config["key_length"]))
        salir = True
    except ValueError as e:
        print(e)
    except Exception as e:
        import sys
        print(e)
        sys.exit()
p = multiprocessing.Process(target=client.listen)
p.start()
client.run()
p.join()
