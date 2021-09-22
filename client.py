#!/usr/bin/env python3

import socket
import json
import time
import signal
from os.path import exists, join
from os import mkdir
from utils import *
from utils_certificat import * 
from utils_encodage import * 
from utils_socket import * 
import base64


if not exists('../certificate'):
    mkdir('../certificate')
def generate_keys(nb_keys):
    tab_temp = []
    name_folder = '../certificate/'+client_type
    if not exists(name_folder):
            mkdir(name_folder)
    for i in range (0,nb_keys):
        keys = create_key()
        tab_temp.append(keys)
        # On enregistre la clé dans le fichier file_key_name
        if not exists(name_folder):
            mkdir(name_folder)
        open(name_folder+'/'+client_type+'.key', 'wt').write( crypto.dump_privatekey (crypto.FILETYPE_PEM, keys).decode() )
    return tab_temp

def create_request(request_type,identity,message,certificate=None,keys=None,signature=None):
    request = {}
    request['identity'] = identity
    request['request_type'] = request_type
    request['message'] = message
    if(request_type=='generate_certificates'):
        tab_keys_decoded = tab_keys_into_str(keys)
        request['keys'] = tab_keys_decoded
    if(request_type=='send_message'):
        request['certificate'] = certificate
        request['signature'] = base64.b64encode(signature).decode()
    if(request_type=='response_message'):
        if certificate:
            request['certificate'] = certificate
    return dict_into_bytes(request)


signal.signal(signal.SIGINT, signal_handler)

# On vérifie qu'on a bien l'argumnt soit receiver ou sender 
if(len(sys.argv) < 2 or (sys.argv[1] != 'sender' and sys.argv[1] != 'receiver')):
    pretty_display('Need argument either \'sender\' or \'receiver\'')
    sys.exit()

# ** PARAMETRE SOCKET ** #
with open('ress/config_socket.json') as json_file:
    socket_config = json.load(json_file)

IPV4 = socket.AF_INET
TCP = socket.SOCK_STREAM

# ** SOCKET SERVER CA ** #
HOST_CA = socket_config['ca']['host']
PORT_CA = socket_config['ca']['port']
TIME_TO_WAIT_CA = socket_config['ca']['time_to_wait']

# ** SOCKET CLIENT RECEIVER ** #
HOST_RECEIVER = socket_config['client_receiver']['host']
PORT_RECEIVER = socket_config['client_receiver']['port']
TIME_TO_WAIT_RECEIVER = socket_config['client_receiver']['time_to_wait']

# ** RECUPERATION TYPE CLIENT ET NOMBRE CERTIFICAT **
client_type  = sys.argv[1]
identity = '--'+client_type.upper()+'--'
nb_certificat = 5
if len(sys.argv) > 2:
    nb_certificat =  int(sys.argv[2])
    pretty_display('\n\n\tBonjour et bienvenue|Vous avez demande '+str(nb_certificat)+' certificats.|\t\t------------------------------|\t\t\tDEBUT : ')
else:
    pretty_display('\n\n\tBonjour et bienvenue|Vous n\'avez pas entre de nombre de certificats. Par defaut : '+str(nb_certificat)+' seront generees|\t\t------------------------------|\t\t\tDEBUT : ')
# Generation des clés
tab_keys_client = generate_keys(nb_certificat)
request = create_request('generate_certificates',client_type,'Genere moi '+str(nb_certificat)+' certificats',None,tab_keys_client,None)

# Connexion au serveur 
is_connect_to_ca = False
with socket.socket(IPV4, TCP) as s:
    while is_connect_to_ca is False:
        pretty_display(identity+' |trying to connect to Server CA ...')
        try : 
            s.connect((HOST_CA, PORT_CA))
            is_connect_to_ca = True
            pretty_display('connected to server CA !')
        except:
            pretty_display('server CA is not running|sleeping for: '+str(TIME_TO_WAIT_CA)+' s\n')
            time.sleep(TIME_TO_WAIT_CA)
    send_msg(s,request)
    data = recv_msg(s)
    dictionaries = dict_from_bytes(data)
    display_new_message(dictionaries)
    dictionaries['certificates'] = tab_certificates_from_bytes(dictionaries['certificates'])
    # On récupère le certificat CA
    certificate_ca = crypto.load_certificate(crypto.FILETYPE_PEM,dictionaries['certificate_ca'])
    # On récupère les certificats que le CA nous a créé
    tab_certificates = tab_certificates_into_str(dictionaries['certificates'])

# LE CLIEN EST UN SENDER 
if(client_type == 'sender'):
    # Connexion au client receiver
    is_connect_to_client_receiver = False
    with socket.socket(IPV4, TCP) as s:
        while is_connect_to_client_receiver is False:
            pretty_display(identity+' |trying to connect to Client receiver ...')
            try : 
                s.connect((HOST_RECEIVER, PORT_RECEIVER))
                is_connect_to_client_receiver = True
                pretty_display('connected to Client receiver!')
            except:
                pretty_display('Client receiver is not running|sleeping for: '+str(TIME_TO_WAIT_RECEIVER)+' s\n')
                time.sleep(TIME_TO_WAIT_RECEIVER)
        # On créé le message
        message = 'Hello, Bonjour, Salam, Hola, je suis '+client_type
        # On récupère la clé privé de notre
        private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, tab_keys_client[0])
        # On créé la signature du message
        signature = crypto.sign(crypto.load_privatekey(crypto.FILETYPE_PEM, private_key.decode()), message.encode(), "sha256")
        # On créé la request en utilisant notre premier certificat
        request = create_request('send_message',client_type,message,tab_certificates[0],None,signature)
        # On envoie 
        send_msg(s,request)
        # On récupère la réponse
        data = recv_msg(s)
        dictionaries = dict_from_bytes(data)
        display_new_message(dictionaries)

# Mise en écoute sur la socket client_receiver
else :
    # On initialise le store avec le certificat du ca. Il nous permettra de vérifier la validité d'un certificat 
    store = crypto.X509Store()
    store.add_cert(certificate_ca)
    with socket.socket(IPV4, TCP) as s:
        s.bind((HOST_RECEIVER, PORT_RECEIVER))
        s.listen()
        pretty_display(identity+' | running|waiting for connection ...')
        conn, addr = s.accept()
        with conn:
            pretty_display('just accepted connection from : '+str(addr)+' socket created ! ')
            data = recv_msg(conn)
            if not data:
                pretty_display('no data received ..')
            else:
                # On récupère le certificat recu
                dictionaries = dict_from_bytes(data)
                display_new_message(dictionaries)
                dictionaries['certificate'] = crypto.load_certificate(crypto.FILETYPE_PEM,dictionaries['certificate'])
                error = None

                # VERIFICATION CERTIFICAT
                try : 
                    store_ctx = crypto.X509StoreContext(store,dictionaries['certificate'])
                    pretty_display('\n|\n|Le certificat est valide|\n')
                except X509StoreContextError:
                    error = '\t\tTon certificat n\'est pas valide\n\n'
                    pretty_display('Le certificat n\'est pas valide')
                if not error : 
                    # VERIFICATION SIGNATURE
                    try:
                        crypto.verify(dictionaries['certificate'], base64.b64decode(dictionaries['signature']), dictionaries['message'].encode(), "sha256")
                        pretty_display('La signature est valide|\n')
                    except crypto.Error:
                        error = '\t\tTa signature n\'est pas valide'
                if not error : 
                    request = create_request('response_message',client_type,'Ton certificat est validé. Ta signature est vérifié. Je t\'envoie le mien',tab_certificates[0],None,None)
                else : 
                    request = request_certificat_invalid = create_request('response_message',client_type,error,None)
                send_msg(conn,request)
                conn.close()

