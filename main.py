from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from db import get_connection
import base64
import hashlib
import hmac
import json
import time

app = FastAPI()

SECRET_KEY = "dev-secret-key"


@app.get("/ping")
def ping():
    return {"message": "pong"}


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
    genre: str | None = None
    genre_id: int | None = None


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def create_access_token(user_id: int) -> str:
    payload = {
        "sub": user_id,
        "exp": int(time.time()) + 3600,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
    sig = hmac.new(
        SECRET_KEY.encode("utf-8"),
        body.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return f"{body}.{sig}"


def decode_access_token(token: str) -> int:
    try:
        body, sig = token.rsplit(".", 1)

        expected_sig = hmac.new(
            SECRET_KEY.encode("utf-8"),
            body.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(sig, expected_sig):
            raise HTTPException(status_code=401, detail="Token invalide")

        padding = "=" * (-len(body) % 4)
        payload_json = base64.urlsafe_b64decode((body + padding).encode("utf-8")).decode("utf-8")
        payload = json.loads(payload_json)

        if int(payload["exp"]) < int(time.time()):
            raise HTTPException(status_code=401, detail="Token expiré")

        return int(payload["sub"])
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Token invalide")


def get_current_user(authorization: str = Header(...)) -> int:
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    else:
        token = authorization.strip()
    return decode_access_token(token)


def resolve_genre_id(conn, genre: str | None = None, genre_id: int | None = None):
    if genre_id is not None:
        row = conn.execute("SELECT ID FROM Genre WHERE ID = ?", (genre_id,)).fetchone()
        return row["ID"] if row else None

    if genre is None:
        return None

    if genre.isdigit():
        row = conn.execute("SELECT ID FROM Genre WHERE ID = ?", (int(genre),)).fetchone()
        if row:
            return row["ID"]

    row = conn.execute("SELECT ID FROM Genre WHERE Type = ?", (genre,)).fetchone()
    return row["ID"] if row else None


@app.post("/register")
def register(body: RegisterBody):
    with get_connection() as conn:
        cursor = conn.cursor()

        existing = cursor.execute(
            "SELECT ID FROM Utilisateur WHERE AdresseMail = ?",
            (body.email,),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Email déjà utilisé")

        hashed = hash_password(body.password)

        cursor.execute(
            "INSERT INTO Utilisateur (AdresseMail, Pseudo, MotDePasse) VALUES (?, ?, ?)",
            (body.email, body.pseudo, hashed),
        )
        conn.commit()
        user_id = cursor.lastrowid

    return {"access_token": create_access_token(user_id), "token_type": "bearer"}


@app.post("/login")
def login(body: LoginBody):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT ID, MotDePasse FROM Utilisateur WHERE AdresseMail = ?",
            (body.email,),
        ).fetchone()

    if row is None or row["MotDePasse"] != hash_password(body.password):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")

    return {"access_token": create_access_token(row["ID"]), "token_type": "bearer"}


@app.post("/film")
def createFilm(film: Film):
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
def getFilms(page: int = 1, per_page: int = 20, genre: str | None = None):
    offset = (page - 1) * per_page

    with get_connection() as conn:
        params = []
        where_sql = ""

        if genre is not None:
            if genre.isdigit():
                where_sql = "WHERE Genre_ID = ?"
                params.append(int(genre))
            else:
                where_sql = "WHERE Genre_ID = (SELECT ID FROM Genre WHERE Type = ?)"
                params.append(genre)

        total = conn.execute(
            f"SELECT COUNT(*) as total FROM Film {where_sql}",
            params,
        ).fetchone()["total"]

        films = conn.execute(
            f"""
            SELECT *
            FROM Film
            {where_sql}
            ORDER BY DateSortie DESC, ID ASC
            LIMIT ? OFFSET ?
            """,
            params + [per_page, offset],
        ).fetchall()

    return {
        "data": [dict(f) for f in films],
        "page": page,
        "per_page": per_page,
        "total": total,
    }


@app.get("/films/{film_id}")
def getFilm(film_id: int):
    with get_connection() as conn:
        film = conn.execute(
            "SELECT * FROM Film WHERE ID = ?",
            (film_id,),
        ).fetchone()

    if film is None:
        raise HTTPException(status_code=404, detail="Film introuvable")

    return dict(film)


@app.get("/genres")
def getGenres():
    with get_connection() as conn:
        genres = conn.execute(
            "SELECT * FROM Genre ORDER BY Type"
        ).fetchall()

    return [dict(g) for g in genres]


@app.post("/preferences")
def add_preference(body: PreferenceBody, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()

        gid = resolve_genre_id(conn, body.genre, body.genre_id)
        if gid is None:
            raise HTTPException(status_code=404, detail="Genre introuvable")

        existing = cursor.execute(
            "SELECT ID FROM Genre_Utilisateur WHERE ID_User = ? AND ID_Genre = ?",
            (user_id, gid),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Genre déjà ajouté")

        cursor.execute(
            "INSERT INTO Genre_Utilisateur (ID_Genre, ID_User) VALUES (?, ?)",
            (gid, user_id),
        )
        conn.commit()

    return {"detail": "Préférence ajoutée"}


@app.delete("/preferences/{genre}")
def remove_preference(genre: str, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()

        gid = resolve_genre_id(conn, genre=genre)
        if gid is None:
            raise HTTPException(status_code=404, detail="Genre introuvable")

        cursor.execute(
            "DELETE FROM Genre_Utilisateur WHERE ID_User = ? AND ID_Genre = ?",
            (user_id, gid),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Préférence introuvable")

        conn.commit()

    return {"detail": "Préférence supprimée"}


@app.get("/recommendations")
def get_recommendations(user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT f.*
            FROM Film f
            JOIN Genre_Utilisateur gu ON gu.ID_Genre = f.Genre_ID
            WHERE gu.ID_User = ?
            ORDER BY f.DateSortie DESC, f.ID ASC
            LIMIT 5
            """,
            (user_id,),
        ).fetchall()

    return [dict(r) for r in rows]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)