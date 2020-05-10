import requests
import sys

# Passo 1
# Receba um CPF
# (por parâmetro, interação com o usuário,
# ou arquivo de configuração, tanto faz)

# Se tiver certificado, deve autenticar e listar os certificados (o alias basta)
# [20:38, 27/04/2020] Mateus: Pode ser em qualquer linguagem
# [20:38, 27/04/2020] Mateus: Sugiro pegar uma linguagem que já tenha biblioteca/função pra fazer requisição HTTPS
# [20:38, 27/04/2020] Mateus: Depois me conta qual linguagem escolheu, e qual biblioteca/função pra HTTPS

parameters = {"client_id": "teste_mateus_torres",
    "client_secret": "f70b0a352b699d73777e4abb8c0b8ca75494c82d",
    "username": "87856279508",
    "password": "063695",
    "grant_type": "password"}

url = "https://apicloudid.hom.vaultid.com.br/v0/oauth/pwd_authorize"

response = requests.post( url, json = parameters )

if (response.status_code != 200 ):
        print("Erro. Status: " + str(response.status_code))
        sys.exit("Erro")

]
