from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from db import get_connection
import time

app = FastAPI()


# =========================
# MODELES
# =========================
class Film(BaseModel):
    id: int | None = None
    nom: str
    note: float | None = None
    dateSortie: int | None = None
    image: str | None = None
    video: str | None = None
    genreId: int | None = None


class RegisterBody(BaseModel):
    email: str
    pseudo: str
    password: str


class LoginBody(BaseModel):
    email: str
    password: str


class PreferenceBody(BaseModel):
    genre_id: int


# =========================
# JWT minimal maison (pas de lib externe)
# =========================
import base64
import json
import hmac
import hashlib

SECRET_KEY = "super-secret-key-change-in-production"

def create_access_token(user_id: int) -> str:
    payload = {"sub": user_id, "exp": int(time.time()) + 3600}
    payload_bytes = json.dumps(payload).encode()
    sig = hmac.new(SECRET_KEY.encode(), payload_bytes, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(payload_bytes + sig).decode()
    return token

def decode_access_token(token: str) -> int:
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        payload_bytes, sig = raw[:-32], raw[-32:]
        expected_sig = hmac.new(SECRET_KEY.encode(), payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected_sig):
            raise HTTPException(status_code=401, detail="Token invalide")
        payload = json.loads(payload_bytes.decode())
        if payload.get("exp", 0) < int(time.time()):
            raise HTTPException(status_code=401, detail="Token expiré")
        return int(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Token invalide")


def get_current_user(authorization: str = Header(..., convert_underscores=False)) -> int:
    if not authorization:
        raise HTTPException(status_code=422, detail="Token manquant")
    token = authorization.split(" ")[1] if " " in authorization else authorization
    return decode_access_token(token)


# =========================
# ROUTES FIXES
# =========================
@app.get("/ping")
def ping():
    return {"message": "pong"}


@app.get("/genres")
def getGenres():
    with get_connection() as conn:
        genres = conn.execute("SELECT * FROM Genre ORDER BY Type ASC").fetchall()
    return [dict(g) for g in genres]


@app.get("/films")
def getFilms(page: int = 1, per_page: int = 20, genre_id: int | None = None):
    offset = (page - 1) * per_page
    where = ""
    params = []
    if genre_id is not None:
        where = "WHERE Genre_ID = ?"
        params.append(genre_id)
    with get_connection() as conn:
        total = conn.execute(f"SELECT COUNT(*) as total FROM Film {where}", params).fetchone()["total"]
        films = conn.execute(
            f"SELECT * FROM Film {where} ORDER BY DateSortie DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()
    return {"data": [dict(f) for f in films], "page": page, "per_page": per_page, "total": total}


@app.get("/films/{film_id}")
def getFilm(film_id: int):
    with get_connection() as conn:
        film = conn.execute("SELECT * FROM Film WHERE ID = ?", (film_id,)).fetchone()
    if film is None:
        raise HTTPException(status_code=404, detail="Film introuvable")
    return dict(film)


# =========================
# ROUTE RECOMMENDATIONS AVANT ROUTES PARAM
# =========================
@app.get("/recommendations")
def get_recommendations(user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT f.*
            FROM Film f
            JOIN Genre_Utilisateur g ON f.Genre_ID = g.ID_Genre
            WHERE g.ID_User = ?
            ORDER BY f.DateSortie DESC
            LIMIT 5
            """,
            (user_id,)
        ).fetchall()
    return [dict(r) for r in rows]


# =========================
# POST /film
# =========================
@app.post("/film")
async def createFilm(film: Film):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO Film (Nom, Note, DateSortie, Image, Video, Genre_ID) VALUES (?, ?, ?, ?, ?, ?)",
            (film.nom, film.note, film.dateSortie, film.image, film.video, film.genreId),
        )
        conn.commit()
        new_id = cursor.lastrowid
        res = conn.execute("SELECT * FROM Film WHERE ID = ?", (new_id,)).fetchone()
    return dict(res)


# =========================
# AUTH
# =========================
@app.post("/auth/register")
def register(body: RegisterBody):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM Utilisateur WHERE AdresseMail = ?", (body.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email déjà utilisé")
        # Hash minimal maison (pas sécurisé pour prod)
        hashed = body.password[::-1]  # juste pour tests
        cursor.execute(
            "INSERT INTO Utilisateur (AdresseMail, Pseudo, MotDePasse) VALUES (?, ?, ?)",
            (body.email, body.pseudo, hashed),
        )
        conn.commit()
        user_id = cursor.lastrowid
    return {"access_token": create_access_token(user_id), "token_type": "bearer"}


@app.post("/auth/login")
def login(body: LoginBody):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ID, MotDePasse FROM Utilisateur WHERE AdresseMail = ?", (body.email,))
        row = cursor.fetchone()
    if row is None or row["MotDePasse"] != body.password[::-1]:
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    return {"access_token": create_access_token(row["ID"]), "token_type": "bearer"}


# =========================
# PREFERENCES
# =========================
@app.post("/preferences", status_code=201)
def add_preference(body: PreferenceBody, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM Genre WHERE ID = ?", (body.genre_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Genre introuvable")
        try:
            cursor.execute(
                "INSERT INTO Genre_Utilisateur (ID_User, ID_Genre) VALUES (?, ?)",
                (user_id, body.genre_id)
            )
            conn.commit()
        except Exception:
            raise HTTPException(status_code=409, detail="Préférence déjà ajoutée")
    return {"detail": "Genre ajouté aux favoris"}


@app.delete("/preferences/{genre_id}")
def remove_preference(genre_id: int, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM Genre_Utilisateur WHERE ID_User = ? AND ID_Genre = ?",
            (user_id, genre_id)
        )
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Préférence introuvable")
    return {"detail": "Genre retiré des favoris"}


# =========================
# LANCEMENT SERVEUR
# =========================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)