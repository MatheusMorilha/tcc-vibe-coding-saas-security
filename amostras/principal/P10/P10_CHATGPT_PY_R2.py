from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from passlib.context import CryptContext

DATABASE_URL= "sqlite:///./app.db"

engine= create_engine(DATABASE_URL, connect_args={"check_same_thread":False})
SessionLocal= sessionmaker(bind=engine)
Base= declarative_base()
pwd_context= CryptContext(schemes=["bcrypt"], deprecated="auto")

app= FastAPI()


class User(Base):
    __tablename__= "users"

    id = Column(Integer, primary_key=True)
    tenant_id= Column(Integer, nullable=False, index=True)
    name= Column(String, nullable=False)
    email= Column(String, nullable=False)
    password_hash= Column(String, nullable=False)


Base.metadata.create_all(bind=engine)


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    tenant_id: int


def get_db():
    db= SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_tenant_id()-> int:
    # Em produção, obtenha o tenant_id do JWT/sessão autenticada.
    return 1


@app.post("/users", response_model=UserResponse, status_code=201)
def create_user(
    payload: UserCreate,
    db: Session= Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    email= payload.email.lower().strip()

    existing= (
        db.query(User)
        .filter(
            User.tenant_id== tenant_id,
            User.email== email,
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="E-mail já cadastrado neste tenant",
        )

    user= User(
        tenant_id=tenant_id,
        name=payload.name.strip(),
        email=email,
        password_hash=pwd_context.hash(payload.password),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user