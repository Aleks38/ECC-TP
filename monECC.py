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


def keygen(filename_base="monECC", max_size=1000):
    attempts = 0
    max_attempts = 10000
    k = None
    Q = None

    while attempts < max_attempts:
        k = random.randint(1, max_size)
        Q = double_and_add(k)

        if Q is not None and isinstance(Q, tuple) and len(Q) == 2:
            test_secret = double_and_add(k, Q)
            if test_secret is not None:
                break
        attempts += 1

    if Q is None:
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


def crypt(target_key_name, message_or_file, sender_keys_name="monECC", input_is_file=False, output_file=None):
    message = ""
    if input_is_file:
        try:
            with open(message_or_file, 'r', encoding='utf-8') as f:
                message = f.read()
        except Exception as e:
            print(f"Erreur lecture fichier d'entrée : {e}")
            return
    else:
        message = message_or_file

    target_file = f"{target_key_name}.pub"
    Qb = read_public_key(target_file)

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

    try:
        aes_key, iv = derive_keys_from_secret(S)
    except ValueError:
        print("Erreur Mathématique : Secret à l'infini. Changez de clés.")
        sys.exit(1)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    output_data = f"{Q_sender[0]}:{Q_sender[1]}:{ciphertext.hex()}"

    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(output_data)
            print(f"Message chiffré écrit dans : {output_file}")
        except Exception as e:
            print(f"Erreur écriture fichier sortie : {e}")
    else:
        print(output_data)


def decrypt(key_name, content_or_file, input_is_file=False, output_file=None):
    encrypted_package = ""
    if input_is_file:
        try:
            with open(content_or_file, 'r') as f:
                encrypted_package = f.read().strip()  # .strip() important pour virer les retours ligne
        except Exception as e:
            print(f"Erreur lecture fichier d'entrée : {e}")
            return
    else:
        encrypted_package = content_or_file

    priv_file = f"{key_name}.priv"
    k = read_private_key(priv_file)

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

        plaintext_str = plaintext.decode('utf-8')

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(plaintext_str)
            print(f"Message déchiffré écrit dans : {output_file}")
        else:
            print(f"Message déchiffré : {plaintext_str}")

    except Exception as e:
        print(f"Échec du déchiffrement.")


def print_help():
    print("""
        Script monECC par Alexy
        Syntaxe :
            monECC <commande> [<clé>] [<texte>] [switchs]
        Commande :
            keygen : Génère une paire de clé
            crytp : Chiffre <texte> pour la clé publique <clé>
            decrytp: Déchiffre <texte> pour la clé privée <clé>
            help : Affiche ce manuel
        Clé :
            Un fichier qui contient une clé publique monECC ("crypt") ou une clé
            privée ("decrypt")
        Texte :
            Une phrase en clair ("crypt") ou une phrase chiffrée ("decrypt")
        Switchs :
            -f <file> permet de choisir le nom des clé générés, monECC.pub et
            monECC.priv par défaut
    """)


def main():
    if len(sys.argv) < 2 or sys.argv[1] == "help":
        print_help()
        return

    command = sys.argv[1]
    raw_args = sys.argv[2:]

    options = {
        'f': "monECC",
        's': 1000,
        'i': None,
        'o': None
    }

    clean_args = []

    skip_next = False
    for i in range(len(raw_args)):
        if skip_next:
            skip_next = False
            continue

        arg = raw_args[i]

        if arg == "-f" and i + 1 < len(raw_args):
            options['f'] = raw_args[i + 1]
            skip_next = True
        elif arg == "-s" and i + 1 < len(raw_args):
            try:
                options['s'] = int(raw_args[i + 1])
            except:
                print("Erreur: -s doit être suivi d'un entier.")
                return
            skip_next = True
        elif arg == "-i" and i + 1 < len(raw_args):
            options['i'] = raw_args[i + 1]
            skip_next = True
        elif arg == "-o" and i + 1 < len(raw_args):
            options['o'] = raw_args[i + 1]
            skip_next = True
        else:
            clean_args.append(arg)

    if command == "keygen":
        keygen(options['f'], options['s'])

    elif command == "crypt":
        if len(clean_args) < 1:
            print("Erreur: crypt nécessite au moins le nom du destinataire.")
            return

        target_name = clean_args[0]

        input_is_file = False

        if options['i']:
            message_input = options['i']
            input_is_file = True
        else:
            if len(clean_args) < 2:
                print("Erreur: crypt nécessite un message (ou l'option -i).")
                return
            message_input = clean_args[1]

        crypt(target_name, message_input, options['f'], input_is_file, options['o'])

    elif command == "decrypt":
        if len(clean_args) < 1:
            print("Erreur: decrypt nécessite au moins le nom de votre clé.")
            return

        my_key_name = clean_args[0]

        input_is_file = False

        if options['i']:
            cipher_input = options['i']
            input_is_file = True
        else:
            if len(clean_args) < 2:
                print("Erreur: decrypt nécessite le cryptogramme (ou l'option -i).")
                return
            cipher_input = clean_args[1]

        decrypt(my_key_name, cipher_input, input_is_file, options['o'])

    else:
        print(f"Commande inconnue : {command}")
        print_help()


if __name__ == "__main__":
    main()
