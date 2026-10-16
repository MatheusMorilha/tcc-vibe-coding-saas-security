from io import BytesIO

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from openpyxl import Workbook
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

DATABASE_URL= "sqlite:///./app.db"

engine= create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread":False},
)

SessionLocal= sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base= declarative_base()


class Cliente(Base):
    __tablename__= "clientes"

    id = Column(Integer, primary_key=True)
    tenant_id= Column(Integer, nullable=False, index=True)
    nome= Column(String, nullable=False)
    documento= Column(String)
    email= Column(String)
    telefone= Column(String)


Base.metadata.create_all(bind=engine)

app= FastAPI()


def get_db():
    db= SessionLocal()

    try:
        yield db
    finally:
        db.close()


def obter_tenant_atual()-> int:
    """
    Em produção, o tenant deve ser obtido de um token/sessão
    autenticado, nunca de um parâmetro fornecido livremente pelo cliente.
    """
    return 1


@app.get("/api/clientes/exportar")
def exportar_clientes(
    db: Session= Depends(get_db),
    tenant_id: int = Depends(obter_tenant_atual),
):
    clientes= (
        db.query(Cliente)
        .filter(Cliente.tenant_id== tenant_id)
        .order_by(Cliente.id)
        .all()
    )

    if not clientes:
        raise HTTPException(
            status_code=404,
            detail="Nenhum cliente encontrado para a empresa.",
        )

    workbook= Workbook()
    worksheet= workbook.active
    worksheet.title= "Clientes"

    worksheet.append(
        [
            "ID",
            "Nome",
            "Documento",
            "E-mail",
            "Telefone",
        ]
    )

    for cliente in clientes:
        worksheet.append(
            [
                cliente.id,
                cliente.nome,
                cliente.documento,
                cliente.email,
                cliente.telefone,
            ]
        )

    arquivo= BytesIO()
    workbook.save(arquivo)
    arquivo.seek(0)

    headers= {
        "Content-Disposition": (
            'attachment; filename="clientes.xlsx"'
        )
    }

    return StreamingResponse(
        arquivo,
        media_type=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
        headers=headers,
    )