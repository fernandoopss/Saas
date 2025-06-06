from fastapi import FastAPI, Depends, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
from jose import JWTError, jwt
from passlib.context import CryptContext
from jinja2 import Template
import weasyprint
import os
from datetime import datetime, timedelta
import psycopg2
import stripe

load_dotenv()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth
SECRET_KEY = os.getenv("JWT_SECRET", "secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Database
def get_db():
    return psycopg2.connect(os.getenv("DATABASE_URL"))

@app.post("/registrar")
def registrar(username: str = Form(...), senha: str = Form(...)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    if cur.fetchone():
        raise HTTPException(status_code=400, detail="Usuário já existe.")
    hashed = pwd_context.hash(senha)
    cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed))
    conn.commit()
    cur.close()
    conn.close()
    return {"mensagem": "Usuário registrado com sucesso!"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (form_data.username,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user or not pwd_context.verify(form_data.password, user[2]):
        raise HTTPException(status_code=400, detail="Usuário ou senha inválidos")
    token = jwt.encode({"sub": user[1], "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

def get_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=403, detail="Token inválido")

@app.post("/gerar_produto")
def gerar_produto(ideia: str = Form(...), user: str = Depends(get_user)):
    from openai import OpenAI
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    prompt = f"Criar um curso com base na ideia: {ideia}"
    resposta = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    conteudo = resposta.choices[0].message.content
    with open("templates/template.html", "r", encoding="utf-8") as f:
        template = Template(f.read())
    html = template.render(titulo="Produto Gerado", conteudo=conteudo.replace("\n", "<br>"))
    pdf_path = "produto.pdf"
    weasyprint.HTML(string=html).write_pdf(pdf_path)
    return FileResponse(pdf_path, media_type="application/pdf", filename="produto.pdf")

@app.post("/criar_checkout")
def criar_checkout(user: str = Depends(get_user)):
    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{
            "price_data": {
                "currency": "brl",
                "product_data": {"name": "Produto Digital IA"},
                "unit_amount": 9900,
            },
            "quantity": 1,
        }],
        mode="payment",
        success_url="https://seusite.com/sucesso",
        cancel_url="https://seusite.com/cancelado",
    )
    return {"url": session.url}
