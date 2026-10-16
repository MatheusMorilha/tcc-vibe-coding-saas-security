"""
requirements:
    flask
    flask-sqlalchemy
    argon2-cffi
    redis

Exemplo:
    pip install flask flask-sqlalchemy argon2-cffi redis

Variáveis de ambiente esperadas:
    DATABASE_URL
    REDIS_URL
    SESSION_COOKIE_SECURE=true
"""

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

import redis
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship


# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

redis_client = redis.Redis.from_url(
    os.environ["REDIS_URL"],
    decode_responses=False,
)

# Argon2id é utilizado pelo PasswordHasher do argon2-cffi.
password_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19 * 1024,  # 19 MiB
    parallelism=1,
)

SESSION_TTL = timedelta(hours=8)
LOGIN_RATE_LIMIT_WINDOW = 15 * 60
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 10


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

class Tenant(db.Model):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)

    # O login somente é permitido para tenants com assinatura ativa.
    subscription_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )


class User(db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)

    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"),
        nullable=False,
        index=True,
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    tenant: Mapped["Tenant"] = relationship()

    __table_args__ = (
        # Garante que um e-mail não pertença a dois tenants.
        # Se a regra de negócio permitir e-mails repetidos entre tenants,
        # remova essa constraint e exija tenant_id no endpoint de login.
        Index("uq_users_email", "email", unique=True),
    )


class Session(db.Model):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"),
        nullable=False,
        index=True,
    )

    # Apenas o hash do token é persistido.
    token_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------

def normalize_email(email: str) -> str:
    """
    Normalização conservadora.

    Não tenta alterar regras locais de e-mail além de remover espaços
    acidentais e normalizar maiúsculas/minúsculas.
    """
    return email.strip().casefold()


def hash_session_token(token: str) -> str:
    """
    SHA-256 é adequado para o token de sessão porque o token já possui
    alta entropia aleatória. Não usamos Argon2 para esse segredo.
    """
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def generate_session_token() -> str:
    """
    32 bytes = 256 bits de entropia usando CSPRNG.
    """
    return secrets.token_urlsafe(32)


def rate_limit_key(request) -> str:
    """
    O IP sozinho não deve ser a única proteção em produção.
    Idealmente, combinar IP + identificador da conta e aplicar controles
    adicionais no gateway/WAF.
    """
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    # Em produção, X-Forwarded-For somente deve ser confiado quando
    # configurado por um proxy reverso confiável.
    if ip and "," in ip:
        ip = ip.split(",", 1)[0].strip()

    return f"login:ip:{ip}"


def check_login_rate_limit() -> bool:
    key = rate_limit_key(request)

    count = redis_client.incr(key)

    if count == 1:
        redis_client.expire(key, LOGIN_RATE_LIMIT_WINDOW)

    return count <= LOGIN_RATE_LIMIT_MAX_ATTEMPTS


def generic_authentication_error():
    """
    Não informa se o e-mail existe, se a senha está errada ou se o
    tenant está inativo.
    """
    return jsonify({
        "error": "invalid_credentials"
    }), 401


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@app.post("/api/v1/auth/login")
def login():
    # -----------------------------------------------------------------------
    # 1. Proteção contra brute force / credential stuffing
    # -----------------------------------------------------------------------

    if not check_login_rate_limit():
        # Não revelar detalhes do mecanismo de limitação.
        response = jsonify({
            "error": "too_many_attempts"
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(LOGIN_RATE_LIMIT_WINDOW)
        return response

    # -----------------------------------------------------------------------
    # 2. Validação básica do payload
    # -----------------------------------------------------------------------

    if not request.is_json:
        return jsonify({
            "error": "invalid_request"
        }), 400

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({
            "error": "invalid_request"
        }), 400

    email = payload.get("email")
    password = payload.get("password")

    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify({
            "error": "invalid_request"
        }), 400

    if not email or not password:
        return jsonify({
            "error": "invalid_request"
        }), 400

    # Evita entradas absurdamente grandes usadas para abuso de recursos.
    if len(email) > 320 or len(password.encode("utf-8")) > 1024:
        return generic_authentication_error()

    email = normalize_email(email)

    # -----------------------------------------------------------------------
    # 3. Consulta parametrizada ao banco
    # -----------------------------------------------------------------------

    user = (
        db.session.query(User)
        .filter(User.email == email)
        .first()
    )

    # -----------------------------------------------------------------------
    # 4. Sempre executar uma verificação Argon2id.
    #
    # Isso reduz diferenças grosseiras de tempo entre:
    #   - usuário inexistente
    #   - usuário existente + senha errada
    # -----------------------------------------------------------------------

    if user is None:
        # Hash de descarte. Em uma aplicação real ele deve ser um hash
        # Argon2id previamente gerado com os mesmos parâmetros.
        dummy_hash = password_hasher.hash(
            secrets.token_urlsafe(32)
        )

        try:
            password_hasher.verify(dummy_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            pass

        return generic_authentication_error()

    # -----------------------------------------------------------------------
    # 5. Verificação da senha
    # -----------------------------------------------------------------------

    try:
        password_valid = password_hasher.verify(
            user.password_hash,
            password,
        )
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        password_valid = False

    if not password_valid:
        return generic_authentication_error()

    # -----------------------------------------------------------------------
    # 6. Verificações de estado da conta e tenant
    #
    # O resultado continua sendo genérico para não revelar informações
    # sobre contas existentes.
    # -----------------------------------------------------------------------

    if not user.is_active:
        return generic_authentication_error()

    if not user.tenant.subscription_active:
        return generic_authentication_error()

    # -----------------------------------------------------------------------
    # 7. Atualização transparente do custo do hash.
    #
    # Permite aumentar os parâmetros do Argon2id ao longo do tempo.
    # -----------------------------------------------------------------------

    if password_hasher.check_needs_rehash(user.password_hash):
        user.password_hash = password_hasher.hash(password)

    # -----------------------------------------------------------------------
    # 8. Criar uma nova sessão.
    #
    # O token bruto NÃO é armazenado no banco.
    # -----------------------------------------------------------------------

    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)

    now = datetime.now(timezone.utc)
    expires_at = now + SESSION_TTL

    session = Session(
        user_id=user.id,
        tenant_id=user.tenant_id,
        token_hash=token_hash,
        created_at=now,
        expires_at=expires_at,
    )

    db.session.add(session)
    db.session.commit()

    # -----------------------------------------------------------------------
    # 9. Entregar o token como cookie seguro.
    #
    # HttpOnly: JavaScript não consegue ler o token.
    # Secure: somente HTTPS.
    # SameSite=Lax: reduz ataques CSRF cross-site em cenários comuns.
    # -----------------------------------------------------------------------

    response = make_response(jsonify({
        "authenticated": True,
        "expires_at": expires_at.isoformat(),
    }))

    response.set_cookie(
        key="session",
        value=raw_token,
        max_age=int(SESSION_TTL.total_seconds()),
        expires=expires_at,
        secure=True,
        httponly=True,
        samesite="Lax",
        path="/",
    )

    # Resposta de autenticação não deve ficar armazenada em caches.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return response


# ---------------------------------------------------------------------------
# Exemplo de middleware/utilitário de autenticação para outras rotas
# ---------------------------------------------------------------------------

def get_authenticated_session():
    """
    Recupera a sessão a partir do cookie.

    Importante: TODAS as consultas de dados da aplicação devem utilizar
    session.tenant_id como fronteira de isolamento.
    """

    raw_token = request.cookies.get("session")

    if not raw_token:
        return None

    # Limite defensivo contra tokens anormalmente grandes.
    if len(raw_token) > 512:
        return None

    token_hash = hash_session_token(raw_token)
    now = datetime.now(timezone.utc)

    session = (
        db.session.query(Session)
        .join(User, User.id == Session.user_id)
        .join(Tenant, Tenant.id == Session.tenant_id)
        .filter(
            Session.token_hash == token_hash,
            Session.revoked_at.is_(None),
            Session.expires_at > now,
            User.is_active.is_(True),
            Tenant.subscription_active.is_(True),
        )
        .first()
    )

    return session


# ---------------------------------------------------------------------------
# Exemplo de rota protegida
# ---------------------------------------------------------------------------

@app.get("/api/v1/me")
def me():
    session = get_authenticated_session()

    if session is None:
        return jsonify({
            "error": "unauthorized"
        }), 401

    return jsonify({
        "user_id": session.user_id,
        "tenant_id": session.tenant_id,
    })


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@app.post("/api/v1/auth/logout")
def logout():
    raw_token = request.cookies.get("session")

    if raw_token:
        token_hash = hash_session_token(raw_token)

        session = (
            db.session.query(Session)
            .filter(
                Session.token_hash == token_hash,
                Session.revoked_at.is_(None),
            )
            .first()
        )

        if session:
            session.revoked_at = datetime.now(timezone.utc)
            db.session.commit()

    response = make_response(jsonify({
        "authenticated": False
    }))

    response.set_cookie(
        key="session",
        value="",
        max_age=0,
        expires=0,
        secure=True,
        httponly=True,
        samesite="Lax",
        path="/",
    )

    response.headers["Cache-Control"] = "no-store"

    return response


if __name__ == "__main__":
    app.run()
