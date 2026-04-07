from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from db import get_connection
import time
import jwt  # PyJWT

app = FastAPI()

SECRET_KEY = "super-secret-key-change-in-production"
ALGORITHM = "HS256"

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
    genre_id: int

def hash_password(password: str) -> str:
    import hashlib
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def create_access_token(user_id: int) -> str:
    payload = {"sub": str(user_id), "exp": int(time.time()) + 3600}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload["sub"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expiré")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide")


def get_current_user(authorization: str = Header(...)) -> int:
    token = authorization.split(" ")[1] if authorization.startswith("Bearer ") else authorization
    return decode_access_token(token)

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
    where_sql = "WHERE Genre_ID = ?" if genre_id else ""
    params = [genre_id] if genre_id else []

    with get_connection() as conn:
        total = conn.execute(f"SELECT COUNT(*) as total FROM Film {where_sql}", params).fetchone()["total"]
        films = conn.execute(
            f"SELECT * FROM Film {where_sql} ORDER BY DateSortie DESC, ID ASC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()

    return {"data": [dict(f) for f in films], "page": page, "per_page": per_page, "total": total}


@app.get("/films/{film_id}")
def getFilm(film_id: int):
    with get_connection() as conn:
        film = conn.execute("SELECT * FROM Film WHERE ID = ?", (film_id,)).fetchone()
    if not film:
        raise HTTPException(status_code=404, detail="Film introuvable")
    return dict(film)


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
        res = conn.execute("SELECT * FROM Film WHERE ID = ?", (new_id,)).fetchone()
    return dict(res)


@app.post("/auth/register")
def register(body: RegisterBody):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM Utilisateur WHERE AdresseMail = ?", (body.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email déjà utilisé")

        pseudo = body.pseudo or body.email.split("@")[0]
        hashed = hash_password(body.password)

        cursor.execute(
            "INSERT INTO Utilisateur (AdresseMail, Pseudo, MotDePasse) VALUES (?, ?, ?)",
            (body.email, pseudo, hashed)
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

    if not row or row["MotDePasse"] != hash_password(body.password):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")

    return {"access_token": create_access_token(row["ID"]), "token_type": "bearer"}


@app.post("/preferences", status_code=201) #Permet à un utilisateur d'ajouter un film en favori
def add_preference(body: PreferenceBody, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM Genre WHERE ID = ?", (body.genre_id,)) #est-ce que le genre que l'utilisateur veut ajouter existe vraiment ?
        if not cursor.fetchone(): 
            raise HTTPException(status_code=404, detail="Genre introuvable") #si le genre n'existe pas en base, on renvoie une erreur 404
        try:
            cursor.execute("INSERT INTO Genre_Utilisateur (ID_User, ID_Genre) VALUES (?, ?)", (user_id, body.genre_id)) #on lie l'utilisateur (user_id) au genre (genre_id)
            conn.commit() #on valide l'écriture dans la base
        except Exception:
            raise HTTPException(status_code=409, detail="Préférence déjà ajoutée") #si le lien existe déjà, la base de données lève une erreur 409
    return {"detail": "Genre ajouté aux favoris"}


@app.delete("/preferences/{genre_id}")
def remove_preference(genre_id: int, user_id: int = Depends(get_current_user)): 
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Genre_Utilisateur WHERE ID_User = ? AND ID_Genre = ?", (user_id, genre_id)) #On tente de supprimer la ligne correspondante
        conn.commit()
        if cursor.rowcount == 0: #cursor.rowcount indique le nombre de lignes supprimées.
        # Si c'est 0, cela veut dire que l'utilisateur n'avait pas ce genre en favori.
            raise HTTPException(status_code=404, detail="Préférence introuvable")
    return {"detail": "Genre retiré des favoris"}


@app.get("/recommendations")
def get_recommendations(user_id: int = Depends(get_current_user)):
    with get_connection() as conn: 
        # On prend les films (f) ET on regarde la table des préférences (g).
        # On ne garde que les films dont le Genre_ID correspond aux genres favoris de l'utilisateur.
        rows = conn.execute(
            "SELECT f.* FROM Film f "
            "JOIN Genre_Utilisateur g ON f.Genre_ID = g.ID_Genre "
            "WHERE g.ID_User = ? " # Uniquement pour cet utilisateur
            "ORDER BY f.DateSortie DESC " # Les plus récents d'abord
            "LIMIT 5", # On s'arrête aux 5 meilleurs résultats
            (user_id,)
        ).fetchall()
    return [dict(r) for r in rows] # On transforme les lignes SQL en dictionnaires JSON pour le client


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)