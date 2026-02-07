# TP MonECC

### **Alexy Da Silva**

## Installation

### Prérequis

* Python 3.x installé sur la machine.

### Dépendances

```bash
pip install cryptography

```

## Utilisation

### 1. Génération de clés (`keygen`)

Génère une paire de clés (publique et privée).
Par défaut, les fichiers sont nommés `monECC.priv` et `monECC.pub`.

**Options disponibles :**

* `-f <nom>` : Donner un nom spécifique aux fichiers.
* `-s <taille>` : Définir la taille maximale de l'aléa (défaut : 1000).

**Exemple :**
Pour l'échange ci-dessous, générez les clés pour **Hugues** (avec une sécurité renforcée via `-s`) et **Alexy** :

```bash
python monECC.py keygen -f Hugues -s 5000
python monECC.py keygen -f Alexy

```

*(Ceci créera 4 fichiers : `Hugues.priv`, `Hugues.pub`, `Alexy.priv` et `Alexy.pub`)*

---

### 2. Chiffrement (`crypt`)

Chiffre un message à destination d'une personne. Le programme utilise automatiquement votre clé privée (si présente via `-f`) pour signer
l'échange.

**Syntaxe :**

```bash
python monECC.py crypt <DESTINATAIRE> "<MESSAGE>" [options]

```

**Options disponibles :**

* `-f <nom>` : Nom de votre clé d'expéditeur (pour signer).
* `-i <fichier>` : Lire le message depuis un fichier texte (Input).
* `-o <fichier>` : Écrire le résultat chiffré dans un fichier (Output).

**Exemple 1 (Message texte) :**
Hugues envoie un message court à Alexy :

```bash
python monECC.py crypt Alexy "Termine le TP avant dimanche 8 février" -f Hugues

```

**Exemple 2 (Fichier vers Fichier) :**
Hugues chiffre le contenu de `secret.txt` pour Alexy et enregistre le résultat dans `message.enc` :

```bash
python monECC.py crypt Alexy -i secret.txt -o message.enc -f Hugues

```

---

### 3. Déchiffrement (`decrypt`)

Déchiffre un cryptogramme en utilisant votre clé privée.

**Syntaxe :**

```bash
python monECC.py decrypt <VOTRE_NOM_CLE> "<CRYPTOGRAMME>" [options]

```

**Options disponibles :**

* `-i <fichier>` : Lire le cryptogramme depuis un fichier (Input).
* `-o <fichier>` : Écrire le message déchiffré (clair) dans un fichier (Output).

**Exemple 1 (Message texte) :**
Alexy déchiffre le message reçu dans le terminal :

```bash
python monECC.py decrypt Alexy "COPIEZ_ICI_LE_RESULTAT_DE_L_ETAPE_PRECEDENTE"

```

**Exemple 2 (Fichier vers Fichier) :**
Alexy déchiffre le fichier `message.enc` et sauvegarde le texte clair dans `revelation.txt` :

```bash
python monECC.py decrypt Alexy -i message.enc -o revelation.txt

```

---