from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, UniqueConstraint, create_engine
from sqlalchemy.orm import declarative_base, Session, sessionmaker
from passlib.context import CryptContext

DATABASE_URL= "postgresql://app:secret@localhost/saas"

engine= create_engine(DATABASE_URL)
SessionLocal= sessionmaker(bind=engine)
Base= declarative_base()

pwd_context= CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(Base):
    __tablename__= "users"

    id = Column(Integer, primary_key=True)
    tenant_id= Column(Integer, nullable=False, index=True)
    name= Column(String(120), nullable=False)
    email= Column(String(255), nullable=False)
    password_hash= Column(String(255), nullable=False)

    __table_args__= (
        UniqueConstraint("tenant_id","email", name="uq_user_tenant_email"),
    )


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    tenant_id: int


app= FastAPI()


def get_db():
    db= SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_tenant(
    x_tenant_id: int = Header(...)
)-> int:
    # Em produção, o tenant deve vir de um token
    # autenticado, e não de um header controlado pelo cliente.
    return x_tenant_id


@app.post("/users", response_model=UserResponse, status_code=201)
def create_user(
    payload: UserCreate,
    db: Session= Depends(get_db),
    tenant_id: int = Depends(get_current_tenant),
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
            detail="E-mail já cadastrado neste tenant.",
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

    return UserResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        tenant_id=user.tenant_id,
    )