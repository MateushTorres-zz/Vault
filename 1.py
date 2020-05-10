import requests

import sys

client_id = "teste_mateus_torres"
client_secret = "f70b0a352b699d73777e4abb8c0b8ca75494c82d"
user_cpf_cnpj = "CPF"
val_cpf_cnpj = "87856279508"

parameters = dict([("client_id", client_id),( "client_secret", client_secret),
                   ("user_cpf_cnpj", user_cpf_cnpj),("val_cpf_cnpj", val_cpf_cnpj)])

url = "https://apicloudid.hom.vaultid.com.br/v0/oauth/user-discovery"

url_authorize = "https://apicloudid.hom.vaultid.com.br/v0/oauth/pwd_authorize"

url_certificate = "https://apicloudid.hom.vaultid.com.br/v0/oauth/certificate-discovery"

#processo de user_discovery
response = requests.post( url, json = parameters )

if (response.status_code != 200 ):
        print("Erro. Status: " + str(response.status_code))
        sys.exit("Erro")

data = response.json()

status = data['status']
if (status == "N"):
        print('Usuário não tem certificado')
        sys.exit("Erro")

slots = data['slots']
primeiro_slot = slots[0]
username = primeiro_slot['slot_alias']
print(username)

#authorize
otp = input("Informe a OTP: ")
parameters = dict([("client_id", client_id),( "client_secret", client_secret),
                   ("username", username ),("password", otp),("grant_type","password" )])

response = requests.post( url_authorize, json = parameters )

if (response.status_code != 200 ):
        print("Erro. Status: " + str(response.status_code))
        sys.exit("Erro")

data = response.json()
print(data)

access_token = data['access_token']

#listando certificados

if (response.status_code != 200 ):
        print("Erro. Status: " + str(response.status_code))
        sys.exit("Erro")

#parameters = dict([('Authorization', access_token)])

hed = {'Authorization': 'Bearer ' + access_token}

response = requests.get( url_certificate, headers = hed )

data = response.json()

print(data)

