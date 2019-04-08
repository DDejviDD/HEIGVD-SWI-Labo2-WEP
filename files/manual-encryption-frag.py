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

# La clé de chiffrement WEP
key = '\xaa\xaa\xaa\xaa\xaa'

# Le message à fragmenter
message = '123456789012345678901234567890123456789012345678901234567890123456789012'

# La capture fournie
arp = rdpcap('arp.cap')[0]

# Fonction de chiffrement d'une donnée
def crypt(data, cap):

    # Calcul de l'icv
    icv = struct.pack('<i', binascii.crc32(data))

    # fragment + icv
    data_bloc = data + icv

    # seed
    seed = cap.iv + key

    # encryption
    return rc4.rc4crypt(data_bloc, seed)


# Fonction de fragmentation d'un message
def frag(message):
    frag_size = 36
    frag_nb = int(math.ceil(len(message) / float(frag_size)))
    plain_frags = frag_nb * [""]
    padding = ' '
    crypted_frags = frag_nb * [""]
    packets = []

    for n in range(frag_nb):
        # Compteur de fragment
        arp.SC = n

        # More frag to come
        if n != frag_nb - 1:
            arp.FCfield |= 0x4  # set the More frag bit
            plain_frags[n] = message[n * frag_size:(n + 1) * frag_size]
        # Last frag (with padding)
        else:
            plain_frags[n] = message[n * frag_size:] + padding * (frag_size - (len(message) % frag_size))

        # Chiffrement du fragment
        crypted_frags[n] = crypt(plain_frags[n], arp)

        # Recupère et stock l'ICV chiffré
        (arp.icv,) = struct.unpack('!L', crypted_frags[n][-4:])

        arp.wepdata = crypted_frags[n][:-4]

        # Ajout de chaque paquet au tableau final
        packets.append(arp)

    # fichier pcap final
    wrpcap('frags.cap', packets)

frag(message)