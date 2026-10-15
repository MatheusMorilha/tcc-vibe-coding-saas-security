from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import String, Integer, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from passlib.context import CryptContext

app= FastAPI()
pwd_context= CryptContext(schemes=["bcrypt"], deprecated="auto")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__= "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    tenant_id: int
    name: str
    email: EmailStr


def get_db()-> Session:
    # Retorne aqui a sessão da sua aplicação.
    raise NotImplementedError


def get_current_tenant_id()-> int:
    # O tenant deve vir do contexto autenticado
    # (por exemplo, token JWT), nunca da requisição.
    raise NotImplementedError


@app.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    data: UserCreate,
    db: Session= Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
):
    email= data.email.lower().strip()

    # Verificação sempre limitada ao tenant atual.
    existing_user= db.scalar(
        select(User).where(
            User.tenant_id== tenant_id,
            User.email== email,
        )
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="E-mail já cadastrado nesta empresa.",
        )

    user= User(
        tenant_id=tenant_id,
        name=data.name.strip(),
        email=email,
        password_hash=pwd_context.hash(data.password),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    # password_hash também não é retornado.
    return UserResponse(
        id=user.id,
        tenant_id=user.tenant_id,
        name=user.name,
        email=user.email,
    )