import multiprocessing


class Handler:

    def __init__(self, interfaz, salir, autosave=True, ipgetting=True):
        """

        Constructor for handler

        :param interfaz: Reference to the interface class
        :param salir: Reference to the control variable
        """
        self.interfaz = interfaz
        self.salir = salir
        m = multiprocessing.Manager()
        self.connections = m.dict()
        self.autosave = autosave
        self.ipgetting = ipgetting

    def recv(self, msg, user):
        """

        Method that handles the incoming messages from the clients

        :param msg: Msg that will parse
        :param user: Reference to the user who disturbed us
        :return: VOID
        """
        command = msg.split("··")
        if command[0] == "say":
            content = msg.replace(command[0]+"··", "")
            self.send_to_all(command[0]+"··"+user.nick+"··"+content)
            self.pantalla("SAY", args=(user.nick, command[1]))
        elif command[0] == "getip":
            if self.ipgetting or command[1] == user.nick:
                try:
                    ip = self.get_user(command[1])
                    user.send("ip··"+command[1]+"··"+str(ip.connection.getpeername()[0]))
                except:
                    user.send("USER_NOT_FOUND··"+command[1])
            else:
                user.send("IP_GETTING_DISABLE")
        elif command[0] == "whisper":
            content = msg.replace(command[0]+"··"+command[1]+"··", "")
            try:
                receiver = self.get_user(command[1])
                receiver.send("whisper··"+user.nick+"··"+content)
            except:
                user.send("USER_NOT_FOUND··"+command[1])
        elif command[0] == "userlist":
            returneo = "userlist··"
            users = self.connections.values()
            for x in users:
                returneo += x.nick + " "
            user.send(returneo)
        else:
            self.pantalla("PROTOCOL_FAILED", args=(msg, user.nick))

    def pantalla(self, msg, args=(), prompt=True, printear=True):
        """

        Handles the output to the console

        :param msg: Key_string to search in the Strings file
        :param args: Args to format into the string
        :param prompt: Shall I print the prompt string at the end of the log?
        :param printear: Shall I print the information or shall I just return the string?
        :return: Generated string
        """
        msg = self.interfaz.get_str(msg)
        if msg:
            msg = msg.format(*args)
            if printear:
                self.interfaz.add_log(msg)
        self.interfaz.printear(self.salir, prompt)
        if self.autosave:
            self.interfaz.log()
        return msg

    def listen(self, server):
        """

        Method to accept commands from the terminal

        :return: VOID
        """
        while not self.salir.value:
            msg = input("")
            try:
                command = msg.split(" ")
                content = msg.replace(command[0]+" ", "")
                if self.salir.value:
                    return True
                self.pantalla("ENTRY_IDENTIFIER", (msg, ))
                if command[0] == self.interfaz.get_str("EXIT"):
                    self.salir.value = True
                elif command[0] == "":
                    pass
                elif command[0] == self.interfaz.get_str("SAY_WORD"):
                    self.pantalla("SERVER_IDENTIFIER", (content, ))
                    self.send_to_all("say··" + self.interfaz.get_str("SERVER") + "··" + content)
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
                elif command[0] == self.interfaz.get_str("GET_IP"):
                    user = self.get_user(command[1])
                    ip = user.connection.getpeername()[0]
                    self.pantalla("IP", args=(command[1], ip))
                elif command[0] == self.interfaz.get_str("USERLIST_WORD"):
                    users = self.connections.values()
                    lista = ""
                    for x in users:
                        lista += x.nick + " "
                    self.pantalla("USERLIST", args=(lista, ))
                elif command[0] == self.interfaz.get_str("KICK"):
                    user = self.get_user(command[1])
                    user.send("KICK")
                    server.delete_client(command[1], notify=False)
                    self.pantalla("KICKED", args=(command[1], ))
                    self.send_to_all("KICKED··"+command[1])
                elif command[0] == self.interfaz.get_str("BAN"):
                    self.ban(command[1], server)
                elif command[0] == self.interfaz.get_str("UNBAN"):
                    self.unban(command[1])
                elif command[0] == self.interfaz.get_str("BANLIST_WORD"):
                    self.banlist()
                elif command[0] == self.interfaz.get_str(""):
                    pass
                else:
                    self.pantalla("COMMAND_NOT_FOUND", args=(command[0], ))
            except Exception as e:
                self.pantalla("FAILED_COMMAND", args=(msg, e))

    def send_to_all(self, msg):
        """
        Sends a message to all the clients
        :param msg: Message to send
        :return: VOID
        """
        clients = self.connections.values()
        for x in clients:
            x.send(msg)

    def exit(self):
        """

        Not sure what an exit method should do :/

        :return: VOID
        """
        self.pantalla("EXITING")
        self.interfaz.log()

    def ban(self, user, server):
        """
        Bans an user from the server
        :param user: User's nick to ban
        :param server: Server object for disconnecting the user
        :return: VOID
        """
        user = self.get_user(user)
        ip = user.connection.getpeername()[0]
        with open("./banlist", "a") as f:
            f.write(user.nick + ":" + str(ip))
        user.send("BAN")
        server.delete_client(user, notify=False)
        self.pantalla("BANNED", args=(user.nick,))
        self.send_to_all("BANNED··" + user.nick)

    def unban(self, user, notify=True):
        """
        Unban an user from the server
        :param user: User's nick to unban
        :param notify: Shall I notify to users?
        :return: VOID
        """
        with open("./banlist", "r") as f:
            lista = list(f.readlines())
            for x in range(0, len(lista)):
                valor = lista[x]
                value = valor.split(":")
                if value[0] == user:
                    lista.pop(x)
                    with open("./banlist", "w") as f:
                        archivo = ""
                        for y in lista:
                            archivo += y
                        f.write(archivo)
                        self.pantalla("UNBANNED", args=(user, ))
                        if notify:
                            self.send_to_all("UNBANNED··"+user)
                        return True
            self.pantalla("USER_NOT_FOUND", args=(user, ))

    def banlist(self):
        """
        Prints the banlist to the server
        :return:
        """
        users = self.get_banned().keys()
        string = ""
        for x in users:
            string += " " + x
        self.pantalla("BANLIST", args=(string, ))

    def get_user(self, user):
        """
        Returns the user object with that nick
        :param user: User to get
        :return: VOID
        """
        try:
            return self.connections[user]
        except:
            raise Exception(self.pantalla("USER_NOT_FOUND", args=(user, ), printear=False))

    def get_banned(self):
        """
        Get the banned list
        :return: Dictionary with the form {nick:ip}
        """
        returneo = {}
        try:
            with open("./banlist", "r") as f:
                for x in f.readlines():
                    data = x.split(":")
                    returneo[data[0]] = data[1].replace("\n", "")
        except FileNotFoundError:
            self.pantalla("BANLIST_NOT_FOUND")
        return returneo
