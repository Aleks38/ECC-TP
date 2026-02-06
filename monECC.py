import base64
import hashlib
import os
import random
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CURVE = {
    'a': 35,
    'b': 3,
    'p': 101
}
P = (2, 9)


def inverse_mod(k, p):
    if k == 0:
        raise ValueError("Division par zéro impossible")
    if k < 0:
        return p - inverse_mod(-k, p)

    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_s % p


def point_add(Pt1, Pt2):
    if Pt1 is None: return Pt2
    if Pt2 is None: return Pt1

    Px, Py = Pt1
    Rx, Ry = Pt2

    p = CURVE['p']
    a = CURVE['a']

    if Px == Rx and Py != Ry:
        return None

    if Px == Rx and Py == Ry:
        if Py == 0: return None

        lmb_num = (3 * Px ** 2 + a)
        lmb_den = inverse_mod(2 * Py, p)
        lmb = (lmb_num * lmb_den) % p
    else:
        lmb_num = (Ry - Py)
        lmb_den = inverse_mod(Rx - Px, p)
        lmb = (lmb_num * lmb_den) % p

    Qx = (lmb ** 2 - Px - Rx) % p
    Qy = (lmb * (Px - Qx) - Py) % p

    return (Qx, Qy)


def double_and_add(k, point=None):
    if point is None:
        point = P

    if k == 0 or point is None:
        return None

    result = None
    addend = point

    while k > 0:
        if k % 2 == 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k //= 2

    return result


def keygen(filename_base="monECC"):
    attempts = 0
    max_attempts = 10000
    k = None
    Q = None

    while attempts < max_attempts:
        k = random.randint(1, 1000)
        Q = double_and_add(k)

        if Q is not None and isinstance(Q, tuple) and len(Q) == 2:
            test_secret = double_and_add(k, Q)
            if test_secret is not None:
                break
        attempts += 1

    if Q is None or attempts >= max_attempts:
        return

    priv_content = f"---begin monECC private key---\n"
    k_b64 = base64.b64encode(str(k).encode()).decode()
    priv_content += f"{k_b64}\n"
    priv_content += f"---end monECC key---"

    with open(f"{filename_base}.priv", "w") as f:
        f.write(priv_content)
    print(f"[+] Clé privée : {filename_base}.priv")

    pub_content = f"---begin monECC public key---\n"
    q_str = f"{Q[0]};{Q[1]}"
    q_b64 = base64.b64encode(q_str.encode()).decode()
    pub_content += f"{q_b64}\n"
    pub_content += f"---end monECC key---"

    with open(f"{filename_base}.pub", "w") as f:
        f.write(pub_content)
    print(f"[+] Clé publique : {filename_base}.pub")


def read_public_key(filename):
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
        if "---begin monECC public key---" not in lines[0]:
            raise ValueError("En-tête invalide")

        b64_data = lines[1].strip()
        coords = base64.b64decode(b64_data).decode().split(';')
        return (int(coords[0]), int(coords[1]))
    except Exception as e:
        print(f"Erreur lecture clé publique ({filename}): {e}")
        sys.exit(1)


def read_private_key(filename):
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
        if "---begin monECC private key---" not in lines[0]:
            raise ValueError("En-tête invalide")

        b64_data = lines[1].strip()
        k = int(base64.b64decode(b64_data).decode())
        return k
    except Exception as e:
        print(f"Erreur lecture clé privée ({filename}): {e}")
        sys.exit(1)


def derive_keys_from_secret(secret_point):
    if secret_point is None:
        raise ValueError("Erreur: Secret partagé est le point à l'infini.")

    secret_bytes = str(secret_point[0]).encode('utf-8')

    sha = hashlib.sha256()
    sha.update(secret_bytes)
    digest = sha.digest()

    iv = digest[:16]
    key = digest[16:]
    return key, iv


def crypt(target_key_name, message, sender_keys_name="monECC"):
    Qb = read_public_key(f"{target_key_name}.pub")

    my_priv_file = f"{sender_keys_name}.priv"

    k_sender = None
    Q_sender = None

    if os.path.exists(my_priv_file):
        try:
            k_sender = read_private_key(my_priv_file)
            Q_sender = double_and_add(k_sender, P)
        except:
            k_sender = None

    if k_sender is None:
        k_sender = random.randint(1, 1000)
        Q_sender = double_and_add(k_sender, P)

    S = double_and_add(k_sender, Qb)

    aes_key, iv = derive_keys_from_secret(S)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    output = f"{Q_sender[0]}:{Q_sender[1]}:{ciphertext.hex()}"
    print(output)


def decrypt(key_name, encrypted_package):
    k = read_private_key(f"{key_name}.priv")

    try:
        parts = encrypted_package.strip().split(':')
        if len(parts) != 3:
            raise ValueError("Format incorrect")

        Q_sender_x = int(parts[0])
        Q_sender_y = int(parts[1])
        ciphertext = bytes.fromhex(parts[2])

        Q_sender = (Q_sender_x, Q_sender_y)
    except Exception as e:
        print(f"Erreur format cryptogramme: {e}")
        return

    S = double_and_add(k, Q_sender)

    try:
        aes_key, iv = derive_keys_from_secret(S)
    except ValueError:
        print("Erreur: Secret invalide dérivé.")
        return

    try:
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        print(f"Message déchiffré : {plaintext.decode('utf-8')}")
    except Exception as e:
        print(f"Échec du déchiffrement.")


def print_help():
    print("""
    Script monECC
    Syntaxe: python monECC.py <commande> [<nom_clé>] [<texte>] [switchs]

    Commandes:
      keygen            : Génère une paire de clés (nom_clé.priv, nom_clé.pub)
      crypt <nom> <msg> : Chiffre <msg> pour la clé publique <nom>.pub
      decrypt <nom> <c> : Déchiffre <c> avec la clé privée <nom>.priv
      help              : Affiche ce manuel

    Switchs:
      -f <file>         : Nom de base des fichiers de l'expéditeur (pour keygen et crypt)
    """)


def main():
    if len(sys.argv) < 2 or sys.argv[1] == "help":
        print_help()
        return

    command = sys.argv[1]
    args = sys.argv[2:]

    filename = "monECC"
    if "-f" in args:
        idx = args.index("-f")
        if idx + 1 < len(args):
            filename = args[idx + 1]
            del args[idx:idx + 2]

    if command == "keygen":
        keygen(filename)

    elif command == "crypt":
        if len(args) < 2:
            print("Erreur: crypt nécessite <nom_clé> <texte>")
            return
        crypt(args[0], args[1], filename)

    elif command == "decrypt":
        if len(args) < 2:
            print("Erreur: decrypt nécessite <nom_clé> <message_chiffré>")
            return
        decrypt(args[0], args[1])

    else:
        print(f"Commande inconnue : {command}")
        print_help()


if __name__ == "__main__":
    main()
