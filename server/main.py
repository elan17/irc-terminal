import multiprocessing
import Library.interfaz
import Library.config
import handler
import server

try:
    config = Library.config.read()
except:
    import sys
    print("FAILED TO OPEN CONFIG FILE, EXITING")
    sys.exit()
man = multiprocessing.Manager()
adios = man.Value(bool, False)
interfaz = Library.interfaz.Interfaz(lang=config["lang"])
hand = handler.Handler(interfaz, adios)
hand.pantalla("INIT", prompt=False)
input("")
key_bits = int(config["key_length"])
hand.pantalla("GENERATING_KEY", args=(key_bits,), prompt=False)
server = server.Server(adios, hand, Library.Encriptacion.genera(key_bits), ip=config["host"], port=int(config["port"]))
g = multiprocessing.Process(target=server.listen)
p = multiprocessing.Process(target=server.server_handler)
p2 = multiprocessing.Process(target=hand.listen, args=(server, ))
p.start()
g.start()
hand.listen(server)
adios.value = True
p.join()
g.join()
server.handler.exit()
