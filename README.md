# Cassiopee

Objectif: Générer automatiquement l'input pour Mulval à partir d'un scan Nessus

Lien vers le projet Mulval: https://github.com/risksense/mulval

Dans ce dépôt vont se trouver des programmes venant du dépôt Mulval ci-dessus et qui ont été modifiés.

Pour traduire un scan Nessus en graphe d'attaque:

$ mulval/utils/nessus_translate.sh <xml_nessus>

--> Cela va notamment générer un fichier nessus.P qu'il faut utiliser comme input pour mulval:

$ mulval/utils/graph_gen.sh nessus.P

Une fois le dépôt récupéré, il ne faut pas oublier de compiler les codes sources ! Il suffit de se placer dans le répertoire racine et d'exécuter make.

Modifications de la variable PATH
--> Création de la variable XSBHOME (logiciel indispensable à Mulval):
export XSBHOME=$HOME/tools/XSB-4-0-0/XSB

--> Ajout de XSB/bin au path
export PATH=$PATH:$XSBHOME/bin

--> Création de la variable d'environnement MULVALROOT
export MULVALROOT=$HOME/tools/mulval

--> Ajout de MULVALROOT/src à PATH (Ne pas oublier de créer le répertoire bin qui dontient 3 sous-répertoires: analyser, metrics et adapter)
export PATH=$PATH:$MULVALROOT/bin

--> Ajout de MULVALROOT/utils à PATH
export PATH=$PATH:$MULVALROOT/utils
