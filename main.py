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
    password: str
    pseudo: str | None = None


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
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return f"{payload_b64}.{signature}"


def decode_access_token(token: str) -> int:
    try:
        payload_b64, signature = token.rsplit(".", 1)
        expected_signature = hmac.new(
            SECRET_KEY.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            raise HTTPException(status_code=401, detail="Token invalide")

        padding = "=" * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode((payload_b64 + padding).encode("utf-8")).decode("utf-8")
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


@app.post("/register")
@app.post("/auth/register")
def register(body: RegisterBody):
    with get_connection() as conn:
        cursor = conn.cursor()

        existing = cursor.execute(
            "SELECT ID FROM Utilisateur WHERE AdresseMail = ?",
            (body.email,),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Email déjà utilisé")

        pseudo = body.pseudo if body.pseudo else body.email.split("@")[0]
        hashed = hash_password(body.password)

        cursor.execute(
            "INSERT INTO Utilisateur (AdresseMail, Pseudo, MotDePasse) VALUES (?, ?, ?)",
            (body.email, pseudo, hashed),
        )
        conn.commit()
        user_id = cursor.lastrowid

    return {"access_token": create_access_token(user_id), "token_type": "bearer"}


@app.post("/login")
@app.post("/auth/login")
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
def getFilms(page: int = 1, per_page: int = 20, genre: str | None = None, genre_id: int | None = None):
    offset = (page - 1) * per_page
    params = []

    if genre is not None:
        where_sql = "JOIN Genre g ON g.ID = f.Genre_ID WHERE g.Type = ?"
        params.append(genre)
    elif genre_id is not None:
        where_sql = "WHERE f.Genre_ID = ?"
        params.append(genre_id)
    else:
        where_sql = ""

    with get_connection() as conn:
        if genre is not None:
            total = conn.execute(
                f"SELECT COUNT(*) AS total FROM Film f {where_sql}",
                params,
            ).fetchone()["total"]

            films = conn.execute(
                f"""
                SELECT f.*
                FROM Film f
                {where_sql}
                ORDER BY f.DateSortie DESC, f.ID ASC
                LIMIT ? OFFSET ?
                """,
                params + [per_page, offset],
            ).fetchall()
        else:
            total = conn.execute(
                f"SELECT COUNT(*) AS total FROM Film f {where_sql}",
                params,
            ).fetchone()["total"]

            films = conn.execute(
                f"""
                SELECT f.*
                FROM Film f
                {where_sql}
                ORDER BY f.DateSortie DESC, f.ID ASC
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
            (film_id,)
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


def resolve_genre_id(conn, genre: str | None = None, genre_id: int | None = None):
    if genre_id is not None:
        row = conn.execute("SELECT ID FROM Genre WHERE ID = ?", (genre_id,)).fetchone()
        return row["ID"] if row else None

    if genre is not None:
        row = conn.execute("SELECT ID FROM Genre WHERE Type = ?", (genre,)).fetchone()
        if row:
            return row["ID"]
        if genre.isdigit():
            row = conn.execute("SELECT ID FROM Genre WHERE ID = ?", (int(genre),)).fetchone()
            if row:
                return row["ID"]

    return None


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