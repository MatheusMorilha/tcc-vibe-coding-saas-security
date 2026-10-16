from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

app = FastAPI()

DATABASE_URL = "postgresql://user:password@localhost/app"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_tenant_id() -> int:
    # Em uma aplicação real, esse valor deve vir
    # do token/autenticação do usuário logado.
    return 123


@app.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db)
):
    tenant_id = get_current_tenant_id()

    # Verifica se o usuário pertence ao tenant autenticado.
    user = db.execute(
        text("""
            SELECT id
            FROM users
            WHERE id = :user_id
              AND tenant_id = :tenant_id
        """),
        {
            "user_id": user_id,
            "tenant_id": tenant_id
        }
    ).fetchone()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="Usuário não encontrado."
        )

    try:
        # Exclusão permanente.
        db.execute(
            text("""
                DELETE FROM users
                WHERE id = :user_id
                  AND tenant_id = :tenant_id
            """),
            {
                "user_id": user_id,
                "tenant_id": tenant_id
            }
        )

        db.commit()

        return {
            "success": True,
            "message": "Usuário removido permanentemente.",
            "user_id": user_id
        }

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Não foi possível remover o usuário."
        )
