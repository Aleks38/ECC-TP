# TP MonECC

### **Alexy Da Silva**

## Installation

### Prérequis

* Python 3.x installé sur la machine.

### Dépendances

```bash
pip install cryptography

```

## 🚀 Utilisation

### 1. Génération de clés (`keygen`)

Génère une paire de clés (publique et privée).
Par défaut, les fichiers sont nommés `monECC.priv` et `monECC.pub`.

```bash
python monECC.py keygen

```

**Option :** Utilisez `-f` pour donner un nom spécifique.
Pour tester un échange complet, **générez les clés pour l'expéditeur (Hugues) ET le destinataire (Alexy)** :

```bash
python monECC.py keygen -f Hugues
python monECC.py keygen -f Alexy
```

*(Ceci créera 4 fichiers : `Hugues.priv`, `Hugues.pub`, `Alexy.priv` et `Alexy.pub`)*

### 2. Chiffrement (`crypt`)

Chiffre un message à destination d'une personne (en utilisant sa clé publique).
Le programme utilise automatiquement votre clé privée (si présente via `-f`) pour signer l'échange.

**Syntaxe :** `python monECC.py crypt <NOM_DESTINATAIRE> "<MESSAGE>"`

Exemple (Hugues envoie un message à Alexy) :

```bash
python monECC.py crypt Alexy "Termine le TP avant dimanche 8 février" -f Hugues

```

*Note :*

* *`Alexy` indique d'utiliser la clé publique `Alexy.pub` (le destinataire).*
* *`-f Hugues` indique d'utiliser la clé privée `Hugues.priv` (l'expéditeur).*

### 3. Déchiffrement (`decrypt`)

Déchiffre un cryptogramme reçu en utilisant votre clé privée.

**Syntaxe :** `python monECC.py decrypt <VOTRE_NOM_CLE> "<CRYPTOGRAMME>"`

Exemple (Alexy déchiffre le message reçu) :

```bash
python monECC.py decrypt Alexy "COPIEZ_ICI_LE_RESULTAT_DE_L_ETAPE_PRECEDENTE"

```

---