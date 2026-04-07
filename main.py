from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from db import get_connection
from passlib.context import CryptContext

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

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

# =====================
# TOKEN SIMPLIFIE
# =====================
def create_token(user_id: int) -> str:
    # pour test local : juste l'ID en string
    return str(user_id)

# =====================
# ROUTES TEST
# =====================
@app.get("/ping")
def ping():
    return {"message": "pong"}

# =====================
# FILMS
# =====================
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
def getFilm(film_id: int):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM Film WHERE ID = ?", (film_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Film introuvable")
    return dict(row)

# =====================
# GENRES
# =====================
@app.get("/genres")
def getGenres():
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM Genre").fetchall()
    return [dict(r) for r in rows]

# =====================
# AUTH REGISTER
# =====================
@app.post("/auth/register")
def register(body: RegisterBody):
    with get_connection() as conn:
        cursor = conn.cursor()
        # Vérifie si l'email existe déjà
        cursor.execute("SELECT ID FROM Utilisateur WHERE AdresseMail = ?", (body.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Email déjà utilisé")
        # hash du mot de passe
        hashed = pwd_context.hash(body.password)
        # insertion
        cursor.execute(
            "INSERT INTO Utilisateur (AdresseMail, Pseudo, MotDePasse) VALUES (?, ?, ?)",
            (body.email, body.pseudo, hashed)
        )
        conn.commit()
        user_id = cursor.lastrowid
    return {"access_token": create_token(user_id), "token_type": "bearer"}

# =====================
# LANCEMENT SERVEUR
# =====================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)