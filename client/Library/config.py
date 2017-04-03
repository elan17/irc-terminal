def read(arch="./config.conf"):  # Reads config
    """
    Reads the config file
    :param arch: File to read
    :return: Content of the file
    """
    returneo = {}
    with open(arch) as f:
        for x in f.readlines():
            x = x.replace(" ", "")
            x = x.replace("\t", "")
            if x[0] != "#" and "=" in x and x != "\n":
                linea = x.split("=")
                returneo[linea[0]] = linea[1].replace("\n", "")
    return returneo
