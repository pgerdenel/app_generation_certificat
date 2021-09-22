import json
from OpenSSL import crypto, SSL

def dict_from_bytes(data_encoded):
    return json.loads(data_encoded.decode())

def dict_into_bytes(dictionaries):
    return json.dumps(dictionaries).encode()

def tab_keys_into_str(tab_keys):
    new_tab = []
    for keys in tab_keys:
        new_tab.append(key_into_str(keys))
    return new_tab

def tab_keys_from_bytes(tab_keys_bytes):
    new_tab = []
    for keys_bytes in tab_keys_bytes:
        keys = crypto.load_publickey(crypto.FILETYPE_PEM,keys_bytes)
        new_tab.append(keys)
    return new_tab

def tab_certificates_into_str(tab_cert):
    new_tab = []
    for cert in tab_cert:
        new_tab.append(certificate_into_str(cert))
    return new_tab

def tab_certificates_from_bytes(tab_cert_bytes):
    new_tab = []
    for cert_bytes in tab_cert_bytes:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM,cert_bytes)
        new_tab.append(cert)
    return new_tab

def key_into_str(keys):
    return crypto.dump_publickey(crypto.FILETYPE_PEM,keys).decode()

def certificate_into_str(certificate):
    return crypto.dump_certificate(crypto.FILETYPE_PEM,certificate).decode()
       
