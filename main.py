from fastapi import FastAPI
from pydantic import BaseModel
from db import get_connection

app = FastAPI()


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
        return {"error": "Film introuvable"}

    return dict(film)



@app.get("/genres")
def getGenres():
    with get_connection() as conn:
        genres = conn.execute("SELECT * FROM Genre").fetchall()

    return [dict(g) for g in genres]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
