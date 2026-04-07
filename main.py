from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from db import get_connection
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta

# =====================
# CONFIG
# =====================
app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

SECRET_KEY = "supersecretkey"  # change en prod
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# =====================
# MODELES
# =====================
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

# =====================
# JWT HELPERS
# =====================
def create_access_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": user_id, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> int:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")

# =====================
# ROUTES PING / FILMS / GENRES
# =====================
@app.get("/ping")
def ping():
    return {"message": "pong"}

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
    offset = (page-1)*per_page
    where = ""
    params = []
    if genre_id is not None:
        where = "WHERE Genre_ID=?"
        params.append(genre_id)
    with get_connection() as conn:
        total = conn.execute(f"SELECT COUNT(*) as total FROM Film {where}", params).fetchone()["total"]
        rows = conn.execute(f"SELECT * FROM Film {where} ORDER BY DateSortie DESC LIMIT ? OFFSET ?", params + [per_page, offset]).fetchall()
    return {"data":[dict(r) for r in rows], "page": page, "per_page": per_page, "total": total}

@app.get("/films/{film_id}")
def getFilm(film_id: int):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM Film WHERE ID=?", (film_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Film introuvable")
    return dict(row)

@app.get("/genres")
def getGenres():
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM Genre").fetchall()
    return [dict(r) for r in rows]

# =====================
# AUTH REGISTER / LOGIN
# =====================
@app.post("/auth/register")
def register(body: RegisterBody):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM Utilisateur WHERE AdresseMail=?", (body.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email déjà utilisé")
        hashed = pwd_context.hash(body.password)
        cursor.execute(
            "INSERT INTO Utilisateur (AdresseMail, Pseudo, MotDePasse) VALUES (?, ?, ?)",
            (body.email, body.pseudo, hashed)
        )
        conn.commit()
        user_id = cursor.lastrowid
    token = create_access_token(user_id)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/login")
def login(body: LoginBody):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ID, MotDePasse FROM Utilisateur WHERE AdresseMail=?", (body.email,))
        row = cursor.fetchone()
    if not row or not pwd_context.verify(body.password, row["MotDePasse"]):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    token = create_access_token(row["ID"])
    return {"access_token": token, "token_type": "bearer"}

# =====================
# PREFERENCES
# =====================
@app.post("/preferences", status_code=201)
def add_preference(body: PreferenceBody, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM Genre WHERE ID=?", (body.genre_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Genre introuvable")
        try:
            cursor.execute("INSERT INTO Genre_Utilisateur (ID_Genre, ID_User) VALUES (?, ?)", (body.genre_id, user_id))
            conn.commit()
        except:
            raise HTTPException(status_code=409, detail="Genre déjà ajouté")
    return {"detail": "Préférence ajoutée"}

@app.delete("/preferences/{genre_id}")
def remove_preference(genre_id: int, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Genre_Utilisateur WHERE ID_Genre=? AND ID_User=?", (genre_id, user_id))
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Préférence introuvable")
    return {"detail": "Préférence supprimée"}

@app.get("/recommendations")
def get_recommendations(user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT f.* FROM Film f
            JOIN Genre_Utilisateur p ON f.Genre_ID=p.ID_Genre
            WHERE p.ID_User=?
            ORDER BY f.DateSortie DESC
            LIMIT 5
            """,
            (user_id,)
        ).fetchall()
    return [dict(r) for r in rows]

# =====================
# SERVEUR
# =====================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)