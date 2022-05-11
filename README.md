# Cassiopee

Objectif: Générer automatiquement l'input pour Mulval à partir d'un scan Nessus

Lien vers le projet Mulval d'origine: https://github.com/risksense/mulval

Dans ce dépôt vont se trouver des programmes venant du dépôt Mulval ci-dessus et qui ont été modifiés.

#### Pour traduire un scan Nessus en graphe d'attaque

$ mulval/utils/nessus_translate.sh <xml_nessus>

--> Cela va notamment générer un fichier nessus.P qu'il faut utiliser comme input pour mulval:

$ mulval/utils/graph_gen.sh nessus.P

#### Modifications de la variable PATH

--> Création de la variable d'environnement MULVALROOT
export MULVALROOT=chemin/vers/le/dépôt/github/mulval		//Exemple : /home/bemba/Cours/Cassiopee/Cassiopee/mulval

--> Ajout des chemins utiles à la variable PATH
export PATH=$PATH:$MULVALROOT/bin:$MULVALROOT/utils

#### Création des répertoires qui vont contenir les fichiers binaires
$ mkdir bin/adapter && mkdir bin/metrics

#### Compilation

Une fois le dépôt récupéré, il ne faut pas oublier de compiler les codes sources ! Il suffit de se placer dans le répertoire racine et d'exécuter make. En cas d'échec de compilation:
$ cd src/adapter && make && make install
$ cd src/metrics && make && make install
$ cd src/attack_graph && make && make install