from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from db import get_connection
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

app = FastAPI()


SECRET_KEY = "dev-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()


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


def create_access_token(user_id: int):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": str(user_id), "exp": expire},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        return int(user_id)
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")


@app.get("/ping")
def ping():
    return {"message": "pong"}


@app.post("/film")
async def createFilm(film: Film):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO Film (Nom, Note, DateSortie, Image, Video, Genre_ID)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (film.nom, film.note, film.dateSortie, film.image, film.video, film.genreId),
        )
        conn.commit()

        new_id = cursor.lastrowid
        res = conn.execute("SELECT * FROM Film WHERE ID = ?", (new_id,)).fetchone()
        return dict(res)


@app.get("/films")
def getFilms(page: int = 1, per_page: int = 20, genre_id: int | None = None):
    offset = (page - 1) * per_page

    where = ""
    params = []

    if genre_id is not None:
        where = "WHERE Genre_ID = ?"
        params.append(genre_id)

    with get_connection() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) as total FROM Film {where}",
            params
        ).fetchone()["total"]

        films = conn.execute(
            f"""
            SELECT * FROM Film
            {where}
            LIMIT ? OFFSET ?
            """,
            params + [per_page, offset]
        ).fetchall()

    return {
        "data": [dict(f) for f in films],
        "page": page,
        "per_page": per_page,
        "total": total
    }


@app.get("/films/{film_id}")
def getFilm(film_id: int):
    with get_connection() as conn:
        film = conn.execute(
            "SELECT * FROM Film WHERE ID = ?",
            (film_id,)
        ).fetchone()

    if film is None:
        raise HTTPException(status_code=404, detail="Film introuvable")

    return dict(film)


@app.get("/genres")
def getGenres():
    with get_connection() as conn:
        genres = conn.execute("SELECT * FROM Genre").fetchall()

    return [dict(g) for g in genres]



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
            (body.email, body.pseudo, hashed),
        )
        conn.commit()

        user_id = cursor.lastrowid

    return {"access_token": create_access_token(user_id), "token_type": "bearer"}


@app.post("/auth/login")
def login(body: LoginBody):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ID, MotDePasse FROM Utilisateur WHERE AdresseMail = ?",
            (body.email,),
        )
        row = cursor.fetchone()

    if row is None or not pwd_context.verify(body.password, row["MotDePasse"]):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")

    return {"access_token": create_access_token(row["ID"]), "token_type": "bearer"}


@app.post("/preferences")
def add_preference(body: PreferenceBody, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO Genre_Utilisateur (ID_Genre, ID_User) VALUES (?, ?)",
                (body.genre_id, user_id),
            )
            conn.commit()
        except:
            raise HTTPException(status_code=400, detail="Genre déjà ajouté")

    return {"message": "Préférence ajoutée"}


@app.delete("/preferences/{genre_id}")
def remove_preference(genre_id: int, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM Genre_Utilisateur WHERE ID_Genre=? AND ID_User=?",
            (genre_id, user_id),
        )
        conn.commit()

    return {"message": "Préférence supprimée"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
