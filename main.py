import base64
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from db import get_connection
from passlib.context import CryptContext

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

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
# TOKEN SIMPLIFIÉ
# =========================
def create_access_token(user_id: int) -> str:
    # simple base64 encodé
    return base64.urlsafe_b64encode(str(user_id).encode()).decode()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> int:
    try:
        user_id = int(base64.urlsafe_b64decode(credentials.credentials.encode()).decode())
        return user_id
    except:
        raise HTTPException(status_code=401, detail="Token invalide")

# =========================
# ROUTES TEST
# =========================
@app.get("/ping")
def ping():
    return {"message": "pong"}

# =========================
# AUTH
# =========================
@app.post("/auth/register")
def register(body: RegisterBody):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM Utilisateur WHERE AdresseMail = ?", (body.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Email déjà utilisé")

        hashed = pwd_context.hash(body.password)
        cursor.execute(
            "INSERT INTO Utilisateur (AdresseMail, Pseudo, MotDePasse) VALUES (?, ?, ?)",
            (body.email, body.pseudo, hashed)
        )
        conn.commit()
        user_id = cursor.lastrowid
    return {"access_token": create_token(user_id), "token_type": "bearer"}

@app.post("/login")
def login(body: LoginBody):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ID, MotDePasse FROM Utilisateur WHERE AdresseMail=?", (body.email,))
        row = cursor.fetchone()
    if row is None or not pwd_context.verify(body.password, row["MotDePasse"]):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    return {"access_token": create_token(row["ID"]), "token_type": "bearer"}

# =====================
# FILMS
# =========================
@app.post("/film")
def createFilm(film: Film):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO Film (Nom, Note, DateSortie, Image, Video, Genre_ID) VALUES (?, ?, ?, ?, ?, ?)",
            (film.nom, film.note, film.dateSortie, film.image, film.video, film.genreId)
        )
        conn.commit()
        new_id = cursor.lastrowid
        row = conn.execute("SELECT * FROM Film WHERE ID = ?", (new_id,)).fetchone()
        return dict(row)

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
        rows = conn.execute(f"SELECT * FROM Film {where} LIMIT ? OFFSET ?", params + [per_page, offset]).fetchall()

    return {"data": [dict(r) for r in rows], "page": page, "per_page": per_page, "total": total}

@app.get("/films/{film_id}")
def get_film(film_id: int):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM Film WHERE ID=?", (film_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Film introuvable")
    return dict(row)

# =========================
# GENRES
# =========================
@app.get("/genres")
def get_genres():
    with get_connection() as conn:
        # Les tests attendent souvent un tri par type
        rows = conn.execute("SELECT * FROM Genre ORDER BY Type ASC").fetchall()
    return [dict(r) for r in rows]

# =========================
# FAVORIS
# =========================
@app.post("/preferences")
def add_preference(body: PreferenceBody, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO Genre_Utilisateur (ID_Genre, ID_User) VALUES (?, ?)",
                (body.genre_id, user_id)
            )
            conn.commit()
        except Exception:
            # Si le couple (genre, user) existe déjà (clé unique en DB)
            raise HTTPException(status_code=409, detail="Genre déjà ajouté")
    return {"message": "Préférence ajoutée"}

@app.delete("/preferences/{genre_id}")
def remove_preference(genre_id: int, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM Genre_Utilisateur WHERE ID_Genre=? AND ID_User=?", 
            (genre_id, user_id)
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Préférence non trouvée")
        conn.commit()
    return {"message": "Préférence supprimée"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
