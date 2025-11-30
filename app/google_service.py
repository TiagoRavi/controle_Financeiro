import os
import json
import gspread
from google.oauth2.service_account import Credentials

def conectar():
    cred_json = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

    if not cred_json:
        raise Exception("Variável GOOGLE_APPLICATION_CREDENTIALS não encontrada!")

    info = json.loads(cred_json)
    creds = Credentials.from_service_account_info(info)
    client = gspread.authorize(creds)
    return client
