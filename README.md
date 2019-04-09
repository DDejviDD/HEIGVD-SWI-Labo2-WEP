# Sécurité des réseaux sans fil
>by Loic Frueh and Dejvid Muaremi
## Laboratoire 802.11 Sécurité WEP

### 1. Déchiffrement manuel de WEP   
- Comparer la sortie du script avec la capture text déchiffrée par Wireshark
  **Résultat du terminal**
  ![Résultat du terminal](./img/part1_terminal.png)
  **Résultat de wireshark**
  ![Résultat de wireshark](./img/part1_wireshark.png)

On voit bien que les textes sont déchiffré de la même manière cependant wireshark garde l'ICV chiffré, toutefois on voit l'indication **correct** par wireshark qui nous indique qu'il est valide.

### 2. Chiffrement manuel de WEP
![Résultat de wireshark](./img/part2_wireshark.png)


### 3. Fragmentation
**Premier fragment**
![Premier fragment](./img/part3_wireshark1.png)
**Fragment intérmediaire**
![Fragment intérmediaire](./img/part3_wireshark2.png)
**Dernier fragment**
![Dernier fragment](./img/part3_wireshark3.png)
