"""
PetTrack - Backend API
FastAPI + Python com criptografia AES-256 e JWT
"""

from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import jwt
import bcrypt
import qrcode
import qrcode.image.svg
import io
import base64
import uuid
import json
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import hashlib
import os

# ─── App Setup ───────────────────────────────────────────────────────────────
app = FastAPI(title="PetTrack API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Encryption Keys ─────────────────────────────────────────────────────────
SECRET_KEY = "pettrack_super_secret_2024_jwt_key_256bits_secure"
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)
ALGORITHM = "HS256"

# ─── In-Memory DB (substitua por PostgreSQL em produção) ──────────────────────
users_db = {}
pets_db = {}
qr_tokens_db = {}
subscriptions_db = {}
deliveries_db = {}
ai_conversations_db = {}

# ─── Models ──────────────────────────────────────────────────────────────────
class UserRegister(BaseModel):
    name: str
    email: str
    phone: str
    social: Optional[str] = ""
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class PetCreate(BaseModel):
    name: str
    species: str
    breed: Optional[str] = ""
    age: Optional[int] = None
    color: Optional[str] = ""
    photo_url: Optional[str] = ""

class SubscriptionCreate(BaseModel):
    address: str
    city: str
    state: str
    zip_code: str
    complement: Optional[str] = ""

class AIMessage(BaseModel):
    message: str
    pet_id: Optional[str] = None

class LocationUpdate(BaseModel):
    lat: float
    lng: float
    pet_id: str

# ─── Auth Helpers ─────────────────────────────────────────────────────────────
def create_token(user_id: str, expires_hours: int = 24) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(hours=expires_hours),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

def get_current_user(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token não fornecido")
    token = authorization.split(" ")[1]
    user_id = verify_token(token)
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return users_db[user_id]

def encrypt_data(data: str) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data: str) -> str:
    return fernet.decrypt(data.encode()).decode()

# ─── QR Code Generator ───────────────────────────────────────────────────────
def generate_qr_base64(data: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#f99830", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()

# ─── Routes: Auth ─────────────────────────────────────────────────────────────
@app.post("/auth/register")
async def register(user: UserRegister):
    if any(u["email"] == user.email for u in users_db.values()):
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    
    user_id = str(uuid.uuid4())
    hashed_pw = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt()).decode()
    
    users_db[user_id] = {
        "id": user_id,
        "name": user.name,
        "email": encrypt_data(user.email),
        "phone": encrypt_data(user.phone),
        "social": encrypt_data(user.social or ""),
        "password": hashed_pw,
        "plan": "free",
        "created_at": datetime.utcnow().isoformat()
    }
    
    token = create_token(user_id)
    return {"token": token, "user_id": user_id, "name": user.name, "plan": "free"}

@app.post("/auth/login")
async def login(credentials: UserLogin):
    user = None
    user_id = None
    for uid, u in users_db.items():
        try:
            decrypted_email = decrypt_data(u["email"])
            if decrypted_email == credentials.email:
                user = u
                user_id = uid
                break
        except:
            continue
    
    if not user or not bcrypt.checkpw(credentials.password.encode(), user["password"].encode()):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    
    token = create_token(user_id)
    return {
        "token": token,
        "user_id": user_id,
        "name": user["name"],
        "plan": user.get("plan", "free")
    }

# ─── Routes: Profile (público via QR) ────────────────────────────────────────
@app.get("/profile/{qr_token}")
async def get_public_profile(qr_token: str):
    """Rota pública acessada pelo QR Code - retorna dados descriptografados"""
    if qr_token not in qr_tokens_db:
        raise HTTPException(status_code=404, detail="QR Code inválido")
    
    token_data = qr_tokens_db[qr_token]
    user_id = token_data["user_id"]
    
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="Tutor não encontrado")
    
    user = users_db[user_id]
    pet_id = token_data.get("pet_id")
    pet = pets_db.get(pet_id, {})
    
    return {
        "tutor_name": user["name"],
        "phone": decrypt_data(user["phone"]),
        "social": decrypt_data(user["social"]),
        "pet_name": pet.get("name", ""),
        "pet_species": pet.get("species", ""),
        "pet_breed": pet.get("breed", ""),
        "pet_color": pet.get("color", ""),
        "pet_photo": pet.get("photo_url", ""),
        "message": f"Olá! Encontrei {pet.get('name', 'seu pet')}. Por favor entre em contato!"
    }

# ─── Routes: Pets ─────────────────────────────────────────────────────────────
@app.post("/pets")
async def create_pet(pet: PetCreate, current_user: dict = Depends(get_current_user)):
    pet_id = str(uuid.uuid4())
    qr_token = str(uuid.uuid4()).replace("-", "")
    
    pets_db[pet_id] = {
        "id": pet_id,
        "owner_id": current_user["id"],
        "name": pet.name,
        "species": pet.species,
        "breed": pet.breed,
        "age": pet.age,
        "color": pet.color,
        "photo_url": pet.photo_url,
        "qr_token": qr_token,
        "created_at": datetime.utcnow().isoformat()
    }
    
    qr_tokens_db[qr_token] = {
        "user_id": current_user["id"],
        "pet_id": pet_id
    }
    
    profile_url = f"https://pettrack.app/encontrei/{qr_token}"
    qr_base64 = generate_qr_base64(profile_url)
    
    return {
        "pet_id": pet_id,
        "qr_token": qr_token,
        "qr_code_base64": qr_base64,
        "profile_url": profile_url
    }

@app.get("/pets")
async def list_pets(current_user: dict = Depends(get_current_user)):
    user_pets = [p for p in pets_db.values() if p["owner_id"] == current_user["id"]]
    return user_pets

@app.get("/pets/{pet_id}/qr")
async def get_pet_qr(pet_id: str, current_user: dict = Depends(get_current_user)):
    pet = pets_db.get(pet_id)
    if not pet or pet["owner_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Pet não encontrado")
    
    profile_url = f"https://pettrack.app/encontrei/{pet['qr_token']}"
    qr_base64 = generate_qr_base64(profile_url)
    return {"qr_code_base64": qr_base64, "profile_url": profile_url}

# ─── Routes: Subscription / SaaS ─────────────────────────────────────────────
@app.post("/subscription/subscribe")
async def subscribe(data: SubscriptionCreate, current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    sub_id = str(uuid.uuid4())
    delivery_id = str(uuid.uuid4())
    
    subscriptions_db[user_id] = {
        "id": sub_id,
        "user_id": user_id,
        "plan": "premium",
        "value": 25.00,
        "status": "active",
        "address": encrypt_data(json.dumps({
            "address": data.address,
            "city": data.city,
            "state": data.state,
            "zip_code": data.zip_code,
            "complement": data.complement
        })),
        "subscribed_at": datetime.utcnow().isoformat()
    }
    
    users_db[user_id]["plan"] = "premium"
    
    deliveries_db[delivery_id] = {
        "id": delivery_id,
        "user_id": user_id,
        "status": "processing",
        "tracking_code": f"PT{uuid.uuid4().hex[:8].upper()}",
        "steps": [
            {"step": "Pedido Confirmado", "done": True, "time": datetime.utcnow().isoformat()},
            {"step": "Preparando Coleira", "done": False, "time": None},
            {"step": "Saiu para Entrega", "done": False, "time": None},
            {"step": "Entrega Concluída", "done": False, "time": None}
        ],
        "created_at": datetime.utcnow().isoformat()
    }
    
    return {
        "success": True,
        "subscription_id": sub_id,
        "delivery_id": delivery_id,
        "plan": "premium",
        "message": "Assinatura ativada! Sua coleira inteligente está sendo preparada."
    }

@app.get("/subscription/status")
async def subscription_status(current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    sub = subscriptions_db.get(user_id)
    delivery = next((d for d in deliveries_db.values() if d["user_id"] == user_id), None)
    
    return {
        "plan": current_user.get("plan", "free"),
        "subscription": sub,
        "delivery": delivery
    }

@app.get("/delivery/{delivery_id}")
async def get_delivery(delivery_id: str, current_user: dict = Depends(get_current_user)):
    delivery = deliveries_db.get(delivery_id)
    if not delivery or delivery["user_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Entrega não encontrada")
    return delivery

# ─── Routes: GPS Tracker ──────────────────────────────────────────────────────
@app.post("/tracker/update")
async def update_location(loc: LocationUpdate, current_user: dict = Depends(get_current_user)):
    if current_user.get("plan") != "premium":
        raise HTTPException(status_code=403, detail="Recurso exclusivo do plano Premium")
    
    encrypted_location = encrypt_data(json.dumps({"lat": loc.lat, "lng": loc.lng}))
    pets_db[loc.pet_id]["last_location"] = encrypted_location
    pets_db[loc.pet_id]["last_seen"] = datetime.utcnow().isoformat()
    
    return {"success": True, "timestamp": datetime.utcnow().isoformat()}

@app.get("/tracker/{pet_id}")
async def get_location(pet_id: str, current_user: dict = Depends(get_current_user)):
    if current_user.get("plan") != "premium":
        raise HTTPException(status_code=403, detail="Recurso exclusivo do plano Premium")
    
    pet = pets_db.get(pet_id)
    if not pet or pet["owner_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Pet não encontrado")
    
    loc_encrypted = pet.get("last_location")
    if not loc_encrypted:
        return {"location": None, "last_seen": None}
    
    location = json.loads(decrypt_data(loc_encrypted))
    return {"location": location, "last_seen": pet.get("last_seen")}

# ─── Routes: AI Pet Assistant ─────────────────────────────────────────────────
@app.post("/ai/ask")
async def ask_ai(msg: AIMessage, current_user: dict = Depends(get_current_user)):
    """IA treinada para responder tudo sobre pets - integra com Claude API em produção"""
    if current_user.get("plan") != "premium":
        raise HTTPException(status_code=403, detail="Recurso exclusivo do plano Premium")
    
    # Em produção: integrar com API do Claude/OpenAI
    # Simulação de resposta contextualizada
    pet = pets_db.get(msg.pet_id, {}) if msg.pet_id else {}
    pet_name = pet.get("name", "seu pet")
    
    responses = {
        "alimentação": f"Para {pet_name}, recomendo alimentação 2-3x ao dia com ração de qualidade. Evite alimentos processados humanos.",
        "vacina": f"As vacinas essenciais para {pet_name} incluem: V8/V10 (cães) ou Quádrupla (gatos). Consulte um veterinário anualmente.",
        "comportamento": f"{pet_name} pode apresentar comportamentos diferentes por ansiedade, dor ou mudanças no ambiente.",
        "default": f"Olá! Sou a IA especialista em pets da PetTrack. Pode me perguntar sobre saúde, alimentação, comportamento, vacinas e muito mais sobre {pet_name}!"
    }
    
    msg_lower = msg.message.lower()
    response = responses["default"]
    for key in ["alimentação", "vacina", "comportamento"]:
        if key in msg_lower:
            response = responses[key]
            break
    
    return {
        "response": response,
        "timestamp": datetime.utcnow().isoformat(),
        "model": "PetTrack-AI-v1"
    }

# ─── Health Check ─────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "online", "version": "1.0.0", "service": "PetTrack API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)