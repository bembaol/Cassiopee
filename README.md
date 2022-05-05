# Cassiopee

Objectif: Générer automatiquement l'input pour Mulval à partir d'un scan Nessus

Lien vers le projet Mulval: https://github.com/risksense/mulval

Dans ce dépôt vont se trouver des programmes venant du dépôt Mulval ci-dessus et qui ont été modifiés.

Pour traduire un scan Nessus en graphe d'attaque:

$ mulval/utils/nessus_translate.sh <xml_nessus>

--> Cela va notamment générer un fichier nessus.P qu'il faut utiliser comme input pour mulval:

$ mulval/utils/graph_gen.sh nessus.P

Une fois le dépôt récupéré, il ne faut pas oublier de compiler les codes sources ! Il suffit de se placer dans le répertoire racine et d'exécuter make.