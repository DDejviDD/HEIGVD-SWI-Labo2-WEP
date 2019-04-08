#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Loic Frueh, Dejvid Muaremi"
__copyright__   = "Copyright 2019, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "loic.frueh@heig-vd.ch, dejvid.muaremi@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
import rc4

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

#Fichier de sortie .cap
output = "output.cap"

#Message secret
plaintext = "Hello World !"

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]  

# rc4 seed est composé de IV+clé
seed = arp.iv+key 

#Calcule l'ICV sur 4 bytes et l'ajoute au texte
icv_enclair=struct.pack('<i', binascii.crc32(plaintext))
plaintext = plaintext + icv_enclair

#Chiffre le message
ciphertext = rc4.rc4crypt(plaintext, seed)

#Recupère et stock l'ICV chiffré
(arp.icv,) = struct.unpack('!L', ciphertext[-4:])

#Envoie le message sans l'ICV
arp.wepdata = ciphertext[:-4]

#Genère le fichier
wrpcap(output, arp)