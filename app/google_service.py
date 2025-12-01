import os
import json
import gspread
from google.oauth2.service_account import Credentials


def conectar():
    # Lê a variável do Render contendo o JSON completo
    cred_json = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")

    if not cred_json:
        raise Exception("Variável GOOGLE_APPLICATION_CREDENTIALS_JSON não encontrada!")

    # Converte string JSON -> dict Python
    try:
        info = json.loads(cred_json)
    except Exception as e:
        raise Exception(f"Erro ao interpretar JSON das credenciais: {e}")

    # Autenticação usando o JSON do service account
    creds = Credentials.from_service_account_info(
        info,
        scopes=["https://www.googleapis.com/auth/spreadsheets"]
    )

    client = gspread.authorize(creds)
    return client
