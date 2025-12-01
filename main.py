from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import hmac
import hashlib
import json
import os
from datetime import datetime
from random import randint
import smtplib
from email.mime.text import MIMEText

# ---------- Config ----------

RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")
GMAIL_EMAIL = os.getenv("GMAIL_EMAIL", "")
GMAIL_PASSWORD = os.getenv("GMAIL_PASSWORD", "")

CODES_DB_PATH = "premium_codes.json"

app = FastAPI(title="SuperBrain Backend")

# Allow frontend (HuggingFace / localhost) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # you can restrict later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Models ----------

class VerifyCodeRequest(BaseModel):
    code: str


# ---------- Helpers ----------

def load_codes():
    if not os.path.exists(CODES_DB_PATH):
        return {}
    with open(CODES_DB_PATH, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_codes(data):
    with open(CODES_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def generate_code():
    # 10-digit numeric code
    return str(randint(1000000000, 9999999999))


def send_email(recipient: str, code: str):
    if not (GMAIL_EMAIL and GMAIL_PASSWORD):
        print("Email skipped - GMAIL_EMAIL or GMAIL_PASSWORD not set")
        return

    msg = MIMEText(
        f"Hi,\n\n"
        f"Thank you for subscribing to SuperBrain AI Premium.\n\n"
        f"Your personal Premium Access Code is:\n\n"
        f"    {code}\n\n"
        f"Paste this code into the SuperBrain AI app to unlock unlimited access.\n\n"
        f"- SuperBrain AI"
    )
    msg["Subject"] = "Your SuperBrain AI Premium Access Code"
    msg["From"] = GMAIL_EMAIL
    msg["To"] = recipient

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(GMAIL_EMAIL, GMAIL_PASSWORD)
        server.sendmail(GMAIL_EMAIL, [recipient], msg.as_string())


def verify_signature(body: bytes, received_sig: str) -> bool:
    if not RAZORPAY_WEBHOOK_SECRET:
        return False
    expected = hmac.new(
        RAZORPAY_WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, received_sig)


# ---------- Routes ----------

@app.get("/")
async def root():
    return {"status": "ok", "service": "superbrain-backend"}


@app.post("/razorpay/webhook")
async def razorpay_webhook(request: Request):
    """
    Razorpay will call this when a payment happens.
    We verify the signature, generate a premium code, store it, send email.
    """
    body = await request.body()
    signature = request.headers.get("X-Razorpay-Signature")

    if not signature or not verify_signature(body, signature):
        raise HTTPException(status_code=400, detail="Invalid signature")

    payload = await request.json()
    try:
        payment = payload["payload"]["payment"]["entity"]
    except KeyError:
        raise HTTPException(status_code=400, detail="Malformed Razorpay payload")

    email = payment.get("email")
    amount = payment.get("amount", 0) / 100
    payment_id = payment.get("id")

    if not email:
        raise HTTPException(status_code=400, detail="No email in payment payload")

    code = generate_code()
    data = load_codes()

    data[code] = {
        "email": email,
        "amount": amount,
        "payment_id": payment_id,
        "created_at": datetime.utcnow().isoformat(),
        "used": False,
    }
    save_codes(data)

    # Send code to user
    send_email(email, code)

    return {"status": "success", "code_sent_to": email}


@app.post("/verify-code")
async def verify_code(body: VerifyCodeRequest):
    """
    Called by the Streamlit UI: checks if a code exists and is not used.
    If valid, marks it as used and returns success.
    """
    code = body.code.strip()
    if not code:
        return {"valid": False, "reason": "empty"}

    data = load_codes()

    if code not in data:
        return {"valid": False, "reason": "not_found"}

    if data[code].get("used"):
        return {"valid": False, "reason": "already_used"}

    # mark as used
    data[code]["used"] = True
    data[code]["used_at"] = datetime.utcnow().isoformat()
    save_codes(data)

    return {"valid": True, "reason": "ok"}


# Optional: simple list (for you; remove in production)
@app.get("/_debug/codes")
async def list_codes():
    return load_codes()
