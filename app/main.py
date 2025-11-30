import os
from flask import Flask, jsonify, request, render_template
from app.google_service import conectar

# ------------------------------------------------------
# FUNÇÃO PARA CONVERTER STR EM NÚMERO (float)
# ------------------------------------------------------
def to_number(value):
    """Converte strings como '1.234,56', '1234,56', '1234.56', 'R$ 1.234,56' em float."""
    
    if isinstance(value, (int, float)):
        return value
    
    if isinstance(value, str):
        # Remove R$, espaços e separadores de milhar
        clean = value.replace("R$", "").replace(".", "").replace(" ", "").strip()
        clean = clean.replace(",", ".")
        try:
            return float(clean)
        except:
            return 0  # fallback seguro
    
    return 0


# Caminhos absolutos para templates e static
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

print(">>> TEMPLATE_DIR:", TEMPLATE_DIR)
print(">>> STATIC_DIR:", STATIC_DIR)

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR
)

# ID da planilha
PLANILHA_ID = "1Sg5_uqU2jrz7uufUVZrg9D-OqAkxHx0uXGdvLbLHKbw"


# ---------------------------
# ROTA PRINCIPAL (Frontend)
# ---------------------------
@app.route("/")
def home():
    return render_template("index.html")


# ---------------------------
# LER DADOS DA PLANILHA
# ---------------------------
@app.route("/rows", methods=["GET"])
def get_rows():
    client = conectar()
    sheet = client.open_by_key(PLANILHA_ID).worksheet("LANCAMENTOS")
    data = sheet.get_all_records(head=4)  # Cabeçalho está na linha 4
    
    # Converter a coluna VALOR em número
    for item in data:
        if "VALOR" in item:
            item["VALOR"] = to_number(item["VALOR"])

    return jsonify(data)


# ---------------------------
# ADICIONAR LINHA NA PLANILHA
# ---------------------------
@app.route("/add", methods=["POST"])
def add_row():
    client = conectar()
    sheet = client.open_by_key(PLANILHA_ID).worksheet("LANCAMENTOS")

    row = request.json.get("row")  # lista: [MES, DATA, CATEGORIA, CONTA, DESCRICAO, VALOR]

    # Converte VALOR antes de salvar
    row[5] = to_number(row[5])

    sheet.append_row(row)

    return jsonify({"status": "ok", "added": row})


# ---------------------------
# EXCLUIR LINHA
# ---------------------------
@app.route("/delete", methods=["POST"])
def delete_row():
    try:
        client = conectar()
        sheet = client.open_by_key(PLANILHA_ID).worksheet("LANCAMENTOS")

        data = request.get_json()
        print("DEBUG delete recebeu:", data)

        if not data or "index" not in data:
            return jsonify({"status": "error", "message": "Index não enviado"}), 400

        index = int(data["index"])
        print("DEBUG deletando linha:", index)

        sheet.delete_rows(index)

        return jsonify({"status": "deleted", "row": index})

    except Exception as e:
        print("⚠️ ERRO NO DELETE:", str(e))
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------
# EXECUÇÃO DO SERVIDOR
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True)
