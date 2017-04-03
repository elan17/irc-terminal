from Library.desurveil import keypair
from Library.desurveil import misc


def genera(bits=1024):
    """
    Generates a RSA key of n bits
    :param bits: Bits of the key
    :return: (Public key, Private key)
    """
    publ, priv = keypair.generate_keypair(bits)
    return(publ.encode().decode(), priv.encode().decode())


def encripta(texto, clave, sistema="base64"):
    """
    Encripts a message for the given public key
    :param texto: Text to encript
    :param clave: Public key
    :param sistema: Cryptographic system to use
    :return: Encrypted code
    """
    rsa = keypair.RSAPublicKey(data=clave, encoding=sistema)
    codificado = rsa.encrypt(texto)
    return misc.encode(codificado, sistema).decode()


def desencripta(texto, clave, sistema="base64"):
    """
    Decrypt a message with the given private key
    :param texto: Text to decrypt
    :param clave: Private key
    :param sistema: Cryptographic system to use
    :return: Decrypted text
    """
    rsa = keypair.RSAPrivateKey(data=clave, encoding=sistema)
    decodificado = rsa.decrypt(misc.decode(texto.encode(), sistema))
    return decodificado.decode()
