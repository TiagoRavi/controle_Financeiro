# app/main.py
import os
import json
from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from authlib.integrations.flask_client import OAuth
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

# Carrega .env automaticamente em dev
load_dotenv()

# ------------------------------------------------------
# SEU CÓDIGO EXISTENTE: converter string -> número
# ------------------------------------------------------
def to_number(value):
    """Converte strings como '1.234,56', '1234,56', '1234.56', 'R$ 1.234,56' em float."""
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        clean = value.replace("R$", "").replace(".", "").replace(" ", "").strip()
        clean = clean.replace(",", ".")
        try:
            return float(clean)
        except:
            return 0
    return 0

# Importa sua função de conexão com Google Sheets
from app.google_service import conectar

# Caminhos absolutos para templates e static (mantive como você estava usando)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Criando app Flask
app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR
)

# Configs
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')

# ------------------------------------------------------
# CONFIGURAÇÃO DE AUTENTICAÇÃO
# ------------------------------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # rota de login
oauth = OAuth(app)

# Registra Google OAuth client (se variáveis estiverem setadas)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
print("🔎 DEBUG GOOGLE_CLIENT_ID:", GOOGLE_CLIENT_ID)
print("🔎 DEBUG GOOGLE_CLIENT_SECRET:", GOOGLE_CLIENT_SECRET)


if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


# ------------------------------------------------------
# Usuários em memória (simples, adequado p/ single-user)
# ------------------------------------------------------
# Estrutura: USERS = { user_id: { "id": user_id, "email":..., "name":..., "password_hash":... } }
USERS = {}

def load_admin_from_env():
    """Carrega usuário admin a partir de variáveis ADMIN_EMAIL e ADMIN_PASSWORD (ou ADMIN_PASSWORD_HASH)."""
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")
    admin_password_hash = os.getenv("ADMIN_PASSWORD_HASH")  # opcional: se você preferir usar hash
    if admin_email and (admin_password or admin_password_hash):
        user_id = f"local:{admin_email}"
        if admin_password_hash:
            pw_hash = admin_password_hash
        else:
            # armazena hash na memória (não no .env)
            pw_hash = generate_password_hash(admin_password)
        USERS[user_id] = {
            "id": user_id,
            "email": admin_email,
            "name": "Admin",
            "password_hash": pw_hash,
            "google": False
        }

# Carrega admin na inicialização
load_admin_from_env()

# Classe User para flask-login
class User(UserMixin):
    def __init__(self, id, email, name=None):
        self.id = id
        self.email = email
        self.name = name or email

@login_manager.user_loader
def load_user(user_id):
    u = USERS.get(user_id)
    if not u:
        return None
    return User(id=u["id"], email=u["email"], name=u.get("name"))

# ------------------------------------------------------
# ROTAS DE AUTENTICAÇÃO
# ------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    # se já autenticado, vai para /
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        # procura usuário local (id prefix local:)
        user_id = f"local:{email}"
        u = USERS.get(user_id)
        if u:
            stored_hash = u.get("password_hash")
            # tenta comparar hash; se por acaso o env guardou senha plain (não recomendado),
            # o generate_password_hash foi aplicado ao carregar.
            if stored_hash and check_password_hash(stored_hash, password):
                user = User(id=user_id, email=u["email"], name=u.get("name"))
                login_user(user)
                flash("Login realizado com sucesso.", "success")
                return redirect(url_for("home"))
        flash("Credenciais inválidas.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Desconectado.", "info")
    return redirect(url_for("login"))

# Google OAuth login
@app.route("/login/google")
def login_google():
    if 'google' not in oauth._registry:
        flash("Google OAuth não configurado.", "danger")
        return redirect(url_for("login"))
    redirect_uri = url_for('authorize_google', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/authorize/google")
def authorize_google():
    token = oauth.google.authorize_access_token()

    if not token:
        flash("Erro na autorização Google.", "danger")
        return redirect(url_for("login"))

    # Obtém o endpoint userinfo do metadata do Google
    userinfo_endpoint = oauth.google.server_metadata.get("userinfo_endpoint")
    userinfo = oauth.google.get(userinfo_endpoint).json()

    email = userinfo.get("email")
    google_id = userinfo.get("sub")  # Google OIDC usa "sub" como identificador único
    name = userinfo.get("name") or email

    if not email:
        flash("Google não retornou email.", "danger")
        return redirect(url_for("login"))

    # cria/atualiza usuário
    user_id = f"google:{google_id}"
    if user_id not in USERS:
        USERS[user_id] = {
            "id": user_id,
            "email": email,
            "name": name,
            "google": True
        }

    user = User(id=user_id, email=email, name=name)
    login_user(user)

    flash("Login com Google realizado.", "success")
    return redirect(url_for("home"))



    # cria/atualiza usuário em USERS (persistirá enquanto o processo rodar)
    user_id = f"google:{google_id}"
    if user_id not in USERS:
        USERS[user_id] = {
            "id": user_id,
            "email": email,
            "name": name,
            "google": True
        }
    user = User(id=user_id, email=email, name=name)
    login_user(user)
    flash("Login com Google realizado.", "success")
    return redirect(url_for("home"))

# ------------------------------------------------------
# SUA LÓGICA EXISTENTE: ID DA PLANILHA + ROTAS
# ------------------------------------------------------
PLANILHA_ID = "1Sg5_uqU2jrz7uufUVZrg9D-OqAkxHx0uXGdvLbLHKbw"

@app.route("/")
@login_required
def home():
    # Se preferir, poderia passar current_user para o template
    return render_template("index.html", user=current_user)

@app.route("/rows", methods=["GET"])
@login_required
def get_rows():
    client = conectar()
    sheet = client.open_by_key(PLANILHA_ID).worksheet("LANCAMENTOS")
    data = sheet.get_all_records(head=4)
    for item in data:
        if "VALOR" in item:
            item["VALOR"] = to_number(item["VALOR"])
    return jsonify(data)

@app.route("/add", methods=["POST"])
@login_required
def add_row():
    client = conectar()
    sheet = client.open_by_key(PLANILHA_ID).worksheet("LANCAMENTOS")

    row = request.json.get("row")
    row[5] = to_number(row[5])
    sheet.append_row(row)
    return jsonify({"status": "ok", "added": row})

@app.route("/delete", methods=["POST"])
@login_required
def delete_row():
    try:
        client = conectar()
        sheet = client.open_by_key(PLANILHA_ID).worksheet("LANCAMENTOS")

        data = request.get_json()
        if not data or "index" not in data:
            return jsonify({"status": "error", "message": "Index não enviado"}), 400

        index = int(data["index"])
        sheet.delete_rows(index)
        return jsonify({"status": "deleted", "row": index})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ---- Início: rotas da dashboard ----
from collections import defaultdict
from flask import request

@app.route("/dashboard")
@login_required
def dashboard():
    # página simples que carrega o frontend do dashboard
    return render_template("dashboard.html")

@app.route("/dashboard-data", methods=["GET"])
@login_required
def dashboard_data():
    """
    Retorna JSON com:
      - months: lista de meses (valores únicos da coluna MES)
      - revenues: dict { categoria: soma }
      - expenses: dict { categoria: soma }
    Aceita parâmetro query string `month` para filtrar, ex: /dashboard-data?month=JAN.
    """

    client = conectar()
    sheet = client.open_by_key(PLANILHA_ID).worksheet("LANCAMENTOS")
    # lê os registros como você já faz (head=4 conforme seu projeto)
    rows = sheet.get_all_records(head=4)

    # extrai mês filtro
    month = request.args.get("month", None)

    # coletores
    rev_by_cat = defaultdict(float)
    exp_by_cat = defaultdict(float)
    months_set = set()

    for r in rows:
        # normaliza chaves (compatível com diferentes formatos de header)
        # tenta obter campos principais
        mes = r.get("MES") or r.get("Mes") or r.get("mes") or ""
        categoria = r.get("CATEGORIA") or r.get("Categoria") or r.get("categoria") or "Sem Categoria"
        tipo = r.get("TIPO") or r.get("Tipo") or r.get("tipo") or None
        valor_raw = r.get("VALOR") or r.get("Valor") or r.get("valor") or 0

        months_set.add(mes)

        # se houver filtro de mês e não bater, pula
        if month and mes != month:
            continue

        # converte para número usando sua função utilitária
        try:
            valor = to_number(valor_raw)
        except Exception:
            valor = 0

        # determina receita/despesa:
        #  - primeiro tenta interpretar coluna TIPO (se existir)
        #  - se não existir ou inconclusivo, usa sinal do valor (>=0 receita)
        is_revenue = None
        if tipo:
            t = str(tipo).strip().lower()
            if "receit" in t or "cred" in t or "entrada" in t or "r" == t:
                is_revenue = True
            elif "desp" in t or "deb" in t or "saida" in t or "saída" in t or "d" == t:
                is_revenue = False

        if is_revenue is None:
            # fallback para sinal
            is_revenue = (valor >= 0)

        if is_revenue:
            rev_by_cat[categoria] += valor
        else:
            # guaranta que despesas fiquem com valor positivo nas somas (para exibição)
            exp_by_cat[categoria] += abs(valor)

    # Ordena os dicts por valor decrescente e transforma em listas para o frontend
    def dict_to_sorted_list(d):
        items = sorted(d.items(), key=lambda x: x[1], reverse=True)
        labels = [i[0] for i in items]
        values = [round(i[1], 2) for i in items]
        return {"labels": labels, "values": values}

    response = {
        "months": sorted(list(months_set)),
        "revenues": dict_to_sorted_list(rev_by_cat),
        "expenses": dict_to_sorted_list(exp_by_cat),
        "selected_month": month
    }

    return jsonify(response)
# ---- Fim: rotas da dashboard ----

# ------------------------------------------------------
# EXECUÇÃO
# ------------------------------------------------------
if __name__ == "__main__":
    # debug True só localmente
    app.run(debug=True)
