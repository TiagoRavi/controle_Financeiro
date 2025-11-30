import os
import json
import gspread
from google.oauth2.service_account import Credentials

def conectar():
    # Lê a variável de ambiente que contém o JSON inteiro
    cred_json = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

    if not cred_json:
        raise Exception("Variável GOOGLE_APPLICATION_CREDENTIALS não encontrada!")

    # Converte string → dicionário
    info = json.loads(cred_json)

    # Autentica usando o JSON
    creds = Credentials.from_service_account_info(
        info,
        scopes=["https://www.googleapis.com/auth/spreadsheets"]
    )

    client = gspread.authorize(creds)
    return client
