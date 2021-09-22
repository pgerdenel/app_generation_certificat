from OpenSSL import crypto, SSL
from os.path import exists, join
from os import mkdir
from time import gmtime, mktime

def create_key():
        # On créé une nouvelle clé
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)
        return k

def generate_self_certificate(folder_certificat, file_certificat, file_key,data_certificate, key_ca):
        if not exists(folder_certificat):
            mkdir(folder_certificat)
        # On créé un nouveau certificat
        cert = crypto.X509()
        cert.get_subject().countryName  = data_certificate['countryName'];
        cert.get_subject().stateOrProvinceName  = data_certificate['stateOrProvinceName'];
        cert.get_subject().localityName  = data_certificate['localityName'];
        cert.get_subject().organizationName  = data_certificate['organizationName'];
        cert.get_subject().organizationalUnitName  = data_certificate['organizationalUnitName'];
        cert.get_subject().commonName  = data_certificate['commonName'];
        cert.get_subject().emailAddress = data_certificate['emailAddress'];
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        # Temps de validité du certificat
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        # On signe le propriétaire  la clé du CA 
        cert.set_pubkey(key_ca)
        # On signe avec la clé du CA
        cert.sign(key_ca, 'sha1')

        # On enregistre la clé dans le fichier file_key_name
        open(folder_certificat+"/"+file_key, "wt").write( crypto.dump_privatekey(crypto.FILETYPE_PEM, key_ca).decode() )
    
        # On enregistre le certificat dans le fichier file_certificate_name
        open(folder_certificat+"/"+file_certificat, "wt").write( crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode() )

        return cert

def generate_certificates(folder_certificat, file_certificat, data_certificate, certificat_ca, key_ca,tab_keys):
        i = 0 
        tab_cert = []
        if not exists(folder_certificat):
                mkdir(folder_certificat)
        for keys in tab_keys:
                # On créé un nouveau certificat
                cert = crypto.X509()
                cert.get_subject().countryName  = data_certificate['countryName'];
                cert.get_subject().stateOrProvinceName  = data_certificate['stateOrProvinceName'];
                cert.get_subject().localityName  = data_certificate['localityName'];
                cert.get_subject().organizationName  = data_certificate['organizationName'];
                cert.get_subject().organizationalUnitName  = data_certificate['organizationalUnitName'];
                cert.get_subject().commonName  = data_certificate['commonName'];
                cert.get_subject().emailAddress = data_certificate['emailAddress'];
                cert.set_serial_number(1000)
                cert.gmtime_adj_notBefore(0)
                # Temps de validité du certificat
                cert.gmtime_adj_notAfter(10*365*24*60*60)
                cert.set_issuer(certificat_ca.get_subject())
                # On signe le propriétaire  la clé du CA 
                cert.set_pubkey(keys)
                # On signe avec la clé du CA
                cert.sign(key_ca, 'sha1')
        
                # On ajoute le certificiat a la liste de certificat
                tab_cert.append(cert)
                
                # On enregistre le certificat dans le fichier file_certificate_name
                open(folder_certificat+"/"+str(i)+file_certificat, "wt").write( crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode() )
                i = i + 1  
        return tab_cert

