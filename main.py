from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from db import get_connection
import time
import jwt  

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


def get_current_user(authorization: str = Header(...)) -> int: #pour relier le token à l'utilisateur
    token = authorization.split(" ")[1] if authorization.startswith("Bearer ") else authorization #on s'assure du bon format du token genre que y a pas de "Bearer " devant
    return decode_access_token(token)

@app.get("/ping") #test de base pour vérifier que ca fonctionne
def ping():
    return {"message": "pong"}


@app.get("/genres")#récupérer la liste des genres
def getGenres():
    with get_connection() as conn:
        genres = conn.execute("SELECT * FROM Genre ORDER BY Type ASC").fetchall()
    return [dict(g) for g in genres]

#récupérer la liste des films avec pagination et on filtre par genre 
@app.get("/films")#route get
def getFilms(page: int = 1, per_page: int = 20, genre_id: int | None = None):
    offset = (page - 1) * per_page#on arrive bien sur le premier film de la page demandée
    where_sql = "WHERE Genre_ID = ?" if genre_id else "" #si y a un genre on les filtre sinon on prend tous les films
    params = [genre_id] if genre_id else []

    with get_connection() as conn:#on se connecte à la base de données
        total = conn.execute(f"SELECT COUNT(*) as total FROM Film {where_sql}", params).fetchone()["total"]#on compte le nombre total de films pour le filtrage demandé pour pouvoir faire la pagination
        films = conn.execute(
            f"SELECT * FROM Film {where_sql} ORDER BY DateSortie DESC, ID ASC LIMIT ? OFFSET ?",#On trie les films
            params + [per_page, offset]
        ).fetchall()#J'ai demandé de l'aide à une IA parce que je maitrise mal le SQL mais je me suis renseigné pour comprendre ce code

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


@app.post("/preferences", status_code=201)
def add_preference(body: PreferenceBody, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ID FROM Genre WHERE ID = ?", (body.genre_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Genre introuvable")
        try:
            cursor.execute("INSERT INTO Genre_Utilisateur (ID_User, ID_Genre) VALUES (?, ?)", (user_id, body.genre_id))
            conn.commit()
        except Exception:
            raise HTTPException(status_code=409, detail="Préférence déjà ajoutée")
    return {"detail": "Genre ajouté aux favoris"}


@app.delete("/preferences/{genre_id}")
def remove_preference(genre_id: int, user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Genre_Utilisateur WHERE ID_User = ? AND ID_Genre = ?", (user_id, genre_id))
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Préférence introuvable")
    return {"detail": "Genre retiré des favoris"}


@app.get("/recommendations")
def get_recommendations(user_id: int = Depends(get_current_user)):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM Film f JOIN Genre_Utilisateur g ON f.Genre_ID = g.ID_Genre "
            "WHERE g.ID_User = ? ORDER BY f.DateSortie DESC LIMIT 5", (user_id,)
        ).fetchall()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)