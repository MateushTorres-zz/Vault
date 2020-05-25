import requests
import hashlib
import sys
import json

def user_discovery(url, parameters):
    response = requests.post(url, json=parameters)

    if (response.status_code != 200):
        print("Erro. Status: " + str(response.status_code))
        sys.exit("Erro")

    data = response.json()

    status = data['status']
    if (status == "N"):
        print('Usuário não tem certificado')
        sys.exit("Erro")

    slots = data['slots']
    username = slots[0]['slot_alias']

    return username


def user_authorize(url, parameters):
    response = requests.post(url_authorize, json=parameters)

    if (response.status_code != 200):
        print("Erro. Status: " + str(response.status_code))
        sys.exit("Erro")

    data = response.json()

    access_token = data['access_token']

    return access_token


def certificate_discovery(url, access_token):


    hed = {'Authorization': 'Bearer ' + access_token}

    response = requests.get( url_certificate, headers = hed )

    if (response.status_code != 200 ):
            print("Erro. Status: " + str(response.status_code))
            sys.exit("Erro")

    data = response.json()

    certificates = data['certificates']
    alias = certificates[0]['alias']

    return alias

def hash_maker(inputFile):
    openedFile = open(inputFile)
    readFile = openedFile.read()

    sha256Hash = hashlib.sha256(readFile.encode('utf-8'))
    sha256Hashed = sha256Hash.hexdigest()

    return sha256Hashed

def sign(url,alias, sha256Hashed, access_token):

    hashes_array = dict([("id",1),( "alias", "Contrato X"),("hash", sha256Hashed ),
                  ("hash_algorithm", "2.16.840.1.101.3.4.2.1"),("signature_format","CMS")])

    parameters = dict([("certificate_alias", alias),( "hashes", [hashes_array])])

    headers ={'Content-type':'application/json',
              'Accept': 'application/json',
              'Authorization': 'Bearer ' + access_token}

    response = requests.post( url, headers = headers, data = json.dumps(parameters))

    if (response.status_code >= 300 ):
            print("Erro. Status: " + str(response.status_code))
            sys.exit("Erro")

    data = response.json()
    print(data, data.__class__)

    signatures = data['signatures']
    raw_signature = signatures[0]['raw_signature']

    saida = open( inputFile + '.p7s', 'w')
    print(raw_signature, file = saida)
    saida.close()

if __name__ == '__main__':
    client_id = "teste_mateus_torres"
    client_secret = "f70b0a352b699d73777e4abb8c0b8ca75494c82d"
    user_cpf_cnpj = "CPF"
    val_cpf_cnpj = "87856279508"

    url_discovery = "https://apicloudid.hom.vaultid.com.br/v0/oauth/user-discovery"
    url_authorize = "https://apicloudid.hom.vaultid.com.br/v0/oauth/pwd_authorize"
    url_certificate = "https://apicloudid.hom.vaultid.com.br/v0/oauth/certificate-discovery"
    url_signature = "https://apicloudid.hom.vaultid.com.br/v0/oauth/signature"

    #
    # User discovery
    #
    parameters = dict([("client_id", client_id), ("client_secret", client_secret),
                       ("user_cpf_cnpj", user_cpf_cnpj), ("val_cpf_cnpj", val_cpf_cnpj)])

    username = user_discovery(url_discovery, parameters)

    #
    # User authorize
    #

    otp = input("Informe a OTP: ")

    parameters = dict([("client_id", client_id), ("client_secret", client_secret), ("username", username),
                       ("password", otp), ("scope", "single_signature"), ("grant_type", "password")])

    access_token = user_authorize(url_authorize, parameters)

    #
    # Listando Certificados
    #

    alias = certificate_discovery(url_discovery, access_token)

    #
    # Calculando Hash
    #
    inputFile = input("Digite o nome do arquivo:")

    hash = hash_maker(inputFile)

    #
    # Sign
    #

    sign(url_signature, alias, hash, access_token)

    print("Arquivo assinado com sucesso.")