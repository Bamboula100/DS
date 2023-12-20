import getpass
import itertools
import re
import string
import hashlib
import bcrypt
import pyautogui
import random
connect = False


def format_mail(mail):
    return re.match(r"[^@]+@[^@]+\.[^@]+", mail) is not None


def format_motdepasse(code):
    return any(c.islower() for c in code) and any(c.isupper() for c in code) \
        and any(c.isdigit() for c in code) and any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/" for c in code) \
        and len(code) >= 8


def enregistrement(mail, code):
    hashed_password = hashlib.sha256(code.encode()).hexdigest()
    with open('enregistrement.txt', 'a') as file:
        file.write(f"Email: {mail}, Password: {hashed_password}\n")


def afficher_menu():
    print("Menu:")
    print("1- Hache le mot par sha256")
    print("2- Hache le mot en (bcrypt)")
    print("3- Attaque Force Brute ")
    print("4- Quitter")


# Fonctions_du_menu =(SHA256,Bcrypt,Brute)
def hacher_sha256(mot_de_passe):
    return hashlib.sha256(mot_de_passe.encode()).hexdigest()


def hacher_bcrypt(mot_de_passe):
    salt = bcrypt.gensalt()
    hashed_pwd = bcrypt.hashpw(mot_de_passe.encode(), salt)
    return hashed_pwd.decode()


def attaque_brute(mot_b):
    chars = list(string.printable)
    print(chars)
    mot_b=""
    while mot_b!=pwd :
        mot_b=random.choices(chars,k=len(pwd))
        print("#####",mot_b,"#####")
        if mot_b==list(pwd) :
            print("votre mot de passe est","".join(mot_b))
            break

def verifier_connexion(mail, code):
    with open('enregistrement.txt', 'r') as file:
        for line in file:
            if f'Email: {mail}' in line:
                print("Email existant")
                hashed_password = line.split("Password: ")[1].strip()
                compare = hashlib.sha256(code.encode()).hexdigest()
                if hashed_password == compare:
                    print("Bienvenue ! ")
                    return True
                else:
                    print("Mot de passe incorrect")
                    return False
        print("Email incorrect ou inexistant")
        return False


print("BIENVENUE ")
choix_authentification = input('Choisissez (1) pour vous inscrire,\n Choisissez (2) pour vous connecter ? ')

if choix_authentification == '1':
    for i in range(3):
        while True:
            email = input(f"Entrez l'email de l'étudiant {i + 1}: ")
            if format_mail(email):
                break
            else:
                print('Email invalide. Veuillez réessayer.')

        while True:
            motdepasse = getpass.getpass('Entrez votre mot de passe : ')

            if format_motdepasse(motdepasse):
                break
            else:
                print('Mot de passe invalide. Veuillez réessayer.')

        enregistrement(email, motdepasse)
        print('Inscription réussie.')

    print('Les informations ont été enregistrées dans le fichier enregistrement.txt.')
    print("Voulez vous vous connecter? ' si oui ")


elif choix_authentification == '2':

    while True:
        if not connect:
            email = input("Entrez votre email : ")
            motdepasse = getpass.getpass('Entrez votre mot de passe : ')
            if verifier_connexion(email, motdepasse):
                print('Connexion reussie.')
                connect = True
                break
            else:
                print('Email ou mot de passe incorrect. Veuillez réessayer ou tapez "quitter" pour quitter.')
                reponse = input('Votre choix : ')
                if reponse.lower() == 'quitter':
                    print('Programme terminé.')
                    break

if connect:
    while True:
        afficher_menu()
        choix_menu = input('Choisissez une option du menu : ')
        if choix_menu == '1':
            HashInput = input('Entrez le mot a hacher : ')
            resultat_hash = hacher_sha256(HashInput)
            print(f'Mot hache par sha256 : {resultat_hash}')
            choix_reessayer = input("Voulez-vous reessayer? (o/n  pour quitter) : ").lower()
            if choix_reessayer == 'o':
                continue
            else:
                print("Aurevoir ")
                break

        elif choix_menu == '2':
            mot_a_hasher = input('Entrez le mot a hacher  : ')
            resultat_hash = hacher_bcrypt(mot_a_hasher)
            print(f'Mot hache par bcrypt : {resultat_hash}')
            choix_reessayer = input("Voulez-vous reessayer? (o/n  pour quitter) : ").lower()
            if choix_reessayer == 'o':
                continue
            else:
                print("Aurevoir ")
                break

        elif choix_menu == '3':
            pwd = pyautogui.password("Donnez votre mot de passe")
            attaque_brute(pwd)
            choix_reessayer = input("Voulez-vous reessayer? (o/n pour quitter) : ").lower()
            if choix_reessayer == 'o':
                continue
            else:
                print("Aurevoir ")
                break

        elif choix_menu == '4':
            print('Fin du programme')
            break
        else:
            print('Option invalide. reessayer .')
            break