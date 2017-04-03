import time
import multiprocessing


class Interfaz:

    def __init__(self, lang="EN"):
        from shutil import get_terminal_size
        self.alto = get_terminal_size()[1]
        from multiprocessing import Manager
        m = Manager()
        self.cola = m.list()
        self.lang = lang
        self.strings = self.load_dict()
        self.terminal_locked = multiprocessing.Manager().Value(bool, False)
        self.log_file = ""

    def load_dict(self):
        """
        Load the language dict
        :return: Language dict
        """
        returneo = {}
        lang = "./Strings/"+self.lang+".lang"
        with open(lang) as f:
            for x in f.readlines():
                x = x.replace("\t", "")
                if x[0] != "#" and "=" in x and x != "\n":
                    linea = x.split("=")
                    returneo[linea[0]] = linea[1].replace("\n", "")
        return returneo

    def get_str(self, string):
        """
        Return the string asociated to the key
        :param string: Key string to search on the dict
        :return:
        """
        try:
            return self.strings[string]
        except KeyError:
            self.add_log("WARNING: String " + string + " not found on lang file, it might be corrupted. Expect " +
                         "missfunctions on some parts of the application")
            return False

    def printear(self, salir, prompt=True):
        """
        Refreshes the screen
        :param salir: Control variable to detect if we are in exit protocol
        :param prompt: Shall I print the prompt?
        :return: VOID
        """
        if not self.terminal_locked.value:
            print("\033c")  # Cleans the screen
            for x in self.cola[len(self.cola) - 1 - self.alto:]:
                print(x)
            if not salir.value and prompt:
                print(self.get_str("PROMPT"))

    def log(self, file="./Logs/log_"):
        """
        Writes on the log file the current log
        :param file: File to write in
        :return: VOID
        """
        returneo = ""
        for x in self.cola:
            returneo += x + "\n"
        if self.log_file == "":
            self.log_file = file+time.ctime()+".log"
        with open(self.log_file, "w") as f:
            f.write(returneo)

    def help(self):
        """
        Returns the help file if found
        :return: Help file
        """
        try:
            with open("./Docs/"+self.lang+"/help.txt", "r") as f:
                arch = f.read()
                return arch
        except FileNotFoundError:
            return False

    def add_log(self, txt):
        """
        Add entry to the log
        :param txt: Entry to add
        :return: VOID
        """
        self.cola.append(txt)
