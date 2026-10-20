
from sqlalchemy import (
    Column, Integer, String, ForeignKey,
    DateTime, Numeric
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)


class Invoice(Base):
    __tablename__ = "invoices"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, nullable=False, index=True)
    customer_name = Column(String(255), nullable=False)
    customer_document = Column(String(30), nullable=True)
    description = Column(String(500), nullable=False)
    amount = Column(Numeric(12, 2), nullable=False)
    status = Column(String(30), nullable=False)
    issued_at = Column(DateTime, nullable=False)
