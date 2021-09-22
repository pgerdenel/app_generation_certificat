#!/usr/bin/env python3

import socket
import json
import time
import signal

from utils import *
from utils_certificat import * 
from utils_encodage import * 
from utils_socket import * 
from os.path import exists, join
from struct import unpack

signal.signal(signal.SIGINT, signal_handler)

if not exists('../certificate'):
    mkdir('../certificate')
# Récupération des données du certificat CA + création du certificat du CA
with open('ress/data_certificate.json') as json_file:
    data_certificate = json.load(json_file)

# On génère une clé pour le CA
key_ca = create_key()
cert_ca = generate_self_certificate('../certificate/CA','ca.crt','ca.key',data_certificate['ca'], key_ca)

# ** PARAMETRE SOCKET ** #
with open('ress/config_socket.json') as json_file:
    data = json.load(json_file)
HOST = data['ca']['host']
PORT = data['ca']['port']
IPV4 = socket.AF_INET
TCP = socket.SOCK_STREAM
identity = '--SERVER CA--'


def create_response(dictionaries):
    response={}
    response['identity'] = 'SERVER CA'
    if(dictionaries['request_type'] == 'generate_certificates'):
        dictionaries['keys'] = tab_keys_from_bytes(dictionaries['keys'])
        tab_cert = generate_certificates('../certificate/'+dictionaries['identity'],'certificat.crt',data_certificate[dictionaries['identity']],cert_ca,key_ca,dictionaries['keys'])
        tab_cert_str = tab_certificates_into_str(tab_cert)
        response['certificate_ca']= certificate_into_str(cert_ca)
        response['certificates'] = tab_cert_str
        response['message'] = "Je t\'ai genere "+str(len(tab_cert))+" certificats"
        response['request_type'] = 'Envoie_certificat'
    return dict_into_bytes(response)

with socket.socket(IPV4, TCP) as s:
    s.bind((HOST, PORT))
    s.listen()
    pretty_display('--Server CA--|running')
    while True:
        pretty_display('waiting for connection ...')
        conn, addr = s.accept()
        with conn:
            pretty_display('just accepted connection from : '+str(addr)+' socket created ! ')
            while True:
                data = recv_msg(conn)
                if not data:
                    pretty_display('no data received ..')
                    break 
                dictionaries = dict_from_bytes(data)
                display_new_message(dictionaries)
                response = create_response(dictionaries)
                send_msg(conn,response)











        