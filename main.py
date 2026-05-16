import os
import csv
import time
import json
import pandas as pd
import joblib
import bcrypt

from fastapi import FastAPI, Request, Form, File, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# ------------------------------
# Paths & Configuration
# ------------------------------
MODEL_PATH = os.environ.get("MODEL_PATH", "reports/model_baseline.joblib")
DETECTIONS_CSV = os.environ.get("DETECTIONS_CSV", "detections.csv")
THRESHOLD = float(os.environ.get("THRESHOLD", "0.5"))
DATASET_PATH = "Modified_SQL_Dataset.csv"
USERS_FILE = "users.json"

app = FastAPI(title="Login + SQLi Firewall Demo")

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# ------------------------------
# Load ML Model
# ------------------------------
model = joblib.load(MODEL_PATH)
classes = list(getattr(model, "classes_", []))

# ------------------------------
# Helper Functions
# ------------------------------
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

USERS = load_users()

def log_detection(text, score, label):
    exists = os.path.exists(DETECTIONS_CSV)
    with open(DETECTIONS_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not exists:
            writer.writerow(["timestamp", "text", "score", "label", "model_path"])
        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            text,
            f"{score:.6f}",
            label,
            MODEL_PATH
        ])

def is_malicious(text: str):
    try:
        probs = model.predict_proba([text])[0]
        if "malicious" in classes:
            idx = classes.index("malicious")
            score = float(probs[idx])
        else:
            score = 1.0 if model.predict([text])[0] == "malicious" else 0.0
    except Exception:
        label_pred = model.predict([text])[0]
        score = 1.0 if label_pred == "malicious" else 0.0

    return score >= THRESHOLD, score

# ------------------------------
# Routes
# ------------------------------
@app.get("/", response_class=HTMLResponse)
def get_login(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "message": ""}
    )

@app.post("/login", response_class=HTMLResponse)
def post_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    payload_text = f"username={username}&password={password}"

    malicious, score = is_malicious(payload_text)
    label = "malicious" if malicious else "benign"

    try:
        log_detection(payload_text, score, label)
    except Exception as e:
        print("Logging failed:", e)

    if malicious:
        return templates.TemplateResponse(
            "blocked.html",
            {"request": request, "reason_score": score}
        )

    stored = USERS.get(username)
    if stored and bcrypt.checkpw(password.encode(), stored.encode()):
        return templates.TemplateResponse(
            "welcome.html",
            {"request": request, "user": username}
        )

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "message": "Invalid username or password."}
    )

# ------------------------------
# Registration Routes
# ------------------------------
@app.get("/register", response_class=HTMLResponse)
def get_register(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {"request": request, "message": ""}
    )

@app.post("/register", response_class=HTMLResponse)
def post_register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    if username in USERS:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "message": "❌ Username already exists!"}
        )

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    USERS[username] = hashed_pw
    save_users(USERS)

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "message": "✅ Registration successful! Please log in."}
    )

# ------------------------------
# Dataset Upload Routes
# ------------------------------
@app.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request):
    return templates.TemplateResponse(
        "upload.html",
        {"request": request, "message": ""}
    )

@app.post("/upload", response_class=HTMLResponse)
async def upload_dataset(
    request: Request,
    file: UploadFile = File(...)
):
    try:
        contents = await file.read()
        with open(DATASET_PATH, "wb") as f:
            f.write(contents)

        df = pd.read_csv(DATASET_PATH)
        preview = df.head().to_html(
            classes="table table-striped",
            index=False
        )

        return templates.TemplateResponse(
            "upload.html",
            {
                "request": request,
                "message": f"✅ Dataset '{file.filename}' uploaded successfully!",
                "preview": preview
            }
        )

    except Exception as e:
        return templates.TemplateResponse(
            "upload.html",
            {"request": request, "message": f"❌ Upload failed: {str(e)}"}
        )
