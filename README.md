# Génération de certificat avec pythonn
(pyOpenSSL)

__L'autorité de certification__ qui génère un certificat AUTO SIGNE et délivre des certificats

__Un client 1__ qui échange avec un autre client 
- il demande son certificat au serveur 
- le serveur lui envoie + le certificat AUTO SIGNE
- le client1 envoie son certificat et son message au client 2

__Un client 2__ qui échange avec un autre client 
- il demande son certificat au serveur 
- le serveur lui envoie + le certificat AUTO SIGNE
- le client 2 récupère le certificat et le message du client 1
- il vérifie l'authenticité du certificat du client 1 en utilisant le certificat AUTO SIGNE du CA
