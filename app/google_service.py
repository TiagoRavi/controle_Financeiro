import gspread
from oauth2client.service_account import ServiceAccountCredentials

def conectar():
    scope = ["https://www.googleapis.com/auth/spreadsheets"]
    creds = ServiceAccountCredentials.from_json_keyfile_name(
        "credentials/service_account.json",
        scope
    )
    client = gspread.authorize(creds)
    return client
