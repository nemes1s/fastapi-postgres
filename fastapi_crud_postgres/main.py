import base64
import hashlib
from typing import List
import databases
import sqlalchemy
import uuid

import uvicorn
from sqlalchemy.dialects.postgresql import UUID, BYTEA
from fastapi import FastAPI, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import urllib

host_server = os.getenv('POSTGRES_SERVER', 'localhost')
db_server_port = urllib.parse.quote_plus(str(os.getenv('db_server_port', '5432')))
database_name = os.getenv('POSTGRES_DB', 'app')
db_username = urllib.parse.quote_plus(str(os.getenv('POSTGRES_USER', 'postgres')))
db_password = urllib.parse.quote_plus(str(os.getenv('POSTGRES_PASSWORD', 'secret')))
ssl_mode = urllib.parse.quote_plus(str(os.getenv('ssl_mode', 'prefer')))
DATABASE_URL = 'postgresql://{}:{}@{}:{}/{}?sslmode={}'.format(db_username, db_password, host_server, db_server_port,
                                                               database_name, ssl_mode)
database = databases.Database(DATABASE_URL)

metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", UUID(), primary_key=True, default=uuid.uuid4),
    sqlalchemy.Column("firstname", sqlalchemy.String),
    sqlalchemy.Column("lastname", sqlalchemy.String),
    sqlalchemy.Column("username", sqlalchemy.String),
    sqlalchemy.Column("password", BYTEA()),
    sqlalchemy.Column("avatar", BYTEA()),
)

engine = sqlalchemy.create_engine(
    DATABASE_URL, pool_size=3, max_overflow=0
)
metadata.create_all(engine)


class UserIn(BaseModel):
    firstname: str
    lastname: str
    username: str
    password: str


class UserOut(BaseModel):
    def __init__(self, **kwargs):
        avatar = kwargs.pop('avatar')
        super().__init__(**kwargs, avatar=base64.b64encode(avatar))
    id: uuid.UUID
    firstname: str
    lastname: str
    username: str
    avatar: str


app = FastAPI(title="REST API using FastAPI PostgreSQL Async EndPoints")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change for prod env
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


@app.get("/users/", response_model=List[UserOut], status_code=status.HTTP_200_OK)
async def read_users(skip: int = 0, take: int = 20):
    query = users.select().offset(skip).limit(take)
    return await database.fetch_all(query)


@app.get("/users/{user_id}/", response_model=UserOut, status_code=status.HTTP_200_OK)
async def read_users(user_id: str):
    query = users.select().where(users.c.id == user_id)
    return await database.fetch_one(query)


@app.post("/users/", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(firstname: str = Form(...), lastname: str = Form(...), username: str = Form(...),
                      password: str = Form(...), avatar: UploadFile = File(...)):
    avatar_processed = await avatar.read()
    id = uuid.uuid4()
    query = users.insert().values(
        id=id,
        firstname=firstname,
        lastname=lastname,
        username=username,
        password=hash_password(password),
        avatar=avatar_processed
    )
    await database.execute(query)
    return {"id": str(id), "firstname": firstname, "lastname": firstname, "username": username,
            "avatar": base64.b64encode(avatar_processed)}


@app.put("/users/{user_id}/", response_model=UserOut, status_code=status.HTTP_200_OK)
async def update_user(user_id: str, firstname: str = Form(...), lastname: str = Form(...), username: str = Form(...),
                      password: str = Form(...), avatar: UploadFile = File(...)):
    avatar_processed = await avatar.read()
    query = users.update().where(users.c.id == user_id).values(
        firstname=firstname,
        lastname=lastname,
        username=username,
        password=hash_password(password),
        avatar=avatar_processed)
    await database.execute(query)
    return {"id": user_id, "firstname": firstname, "lastname": firstname, "username": username,
            "avatar": base64.b64encode(avatar_processed)}


@app.delete("/users/{user_id}/", status_code=status.HTTP_200_OK)
async def delete_user(user_id: str):
    query = users.delete().where(users.c.id == user_id)
    await database.execute(query)
    return {"message": "User with id: {} deleted successfully!".format(user_id)}


salt = os.getenv('SALT', os.urandom(32))  # store this this


def hash_password(password):
    return hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # It is recommended to use at least 100,000 iterations of SHA-256
    )


def start():
    """Launched with `poetry run start` at root level"""
    uvicorn.run("fastapi_crud_postgres.main:app", host="0.0.0.0", port=8000, reload=True)
