from django.db import models


class FailedAuthAttempt(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    # Nulo quando o tenant não pôde ser identificado (ex.: login em domínio genérico)
    tenant_id = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    identifier = models.CharField(max_length=254, blank=True, db_index=True)  # e-mail/usuário informado
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=2048)
    query_string = models.TextField(blank=True)
    status_code = models.PositiveSmallIntegerField()
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    user_agent = models.CharField(max_length=512, blank=True)
    headers = models.JSONField(default=dict)
    body = models.JSONField(null=True, blank=True)  # já redigido
    body_truncated = models.BooleanField(default=False)
    request_id = models.CharField(max_length=64, blank=True)

    class Meta:
        indexes = [models.Index(fields=["tenant_id", "-created_at"])]
        ordering = ["-created_at"]

import logging
import uuid

from django.conf import settings

from .models import FailedAuthAttempt
from .redaction import parse_and_redact_body, redact_query_string, safe_headers

logger = logging.getLogger(__name__)

# Campos que podem conter o identificador informado pelo usuário
IDENTIFIER_FIELDS = ("email", "username", "login", "user", "usuario")


class FailedAuthLogMiddleware:
    """
    Registra tentativas de autenticação malsucedidas.

    Settings opcionais:
      AUTHLOG_LOGIN_PATHS    = ("/api/auth/login/",)  # rotas onde 400/403 também indicam falha
      AUTHLOG_MAX_BODY_BYTES = 16 * 1024
      AUTHLOG_TRUSTED_PROXY  = False  # True só se houver proxy reverso confiável
    """

    FAILURE_STATUS_ANYWHERE = {401}
    FAILURE_STATUS_ON_LOGIN = {400, 401, 403}

    def __init__(self, get_response):
        self.get_response = get_response
        self.login_paths = tuple(getattr(settings, "AUTHLOG_LOGIN_PATHS", ("/api/auth/login/",)))
        self.max_body = getattr(settings, "AUTHLOG_MAX_BODY_BYTES", 16 * 1024)
        self.trust_proxy = getattr(settings, "AUTHLOG_TRUSTED_PROXY", False)

    def __call__(self, request):
        # Lê o corpo ANTES da view (request.body fica em cache para a view usar).
        raw_body, truncated = self._capture_body(request)

        response = self.get_response(request)

        try:
            if self._is_auth_failure(request, response):
                self._record(request, response, raw_body, truncated)
        except Exception:
            # O log nunca pode derrubar ou alterar a resposta ao cliente.
            logger.exception("Falha ao registrar tentativa de autenticação malsucedida")
        return response

    # -- captura --------------------------------------------------------
    def _capture_body(self, request):
        if request.method not in ("POST", "PUT", "PATCH"):
            return b"", False
        ctype = request.META.get("CONTENT_TYPE", "").split(";")[0].strip().lower()
        if ctype not in ("application/json", "application/x-www-form-urlencoded"):
            return b"", False  # multipart/uploads: não lê, evita consumir stream
        try:
            length = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length > self.max_body:
            return b"", True  # grande demais: não carrega em memória
        try:
            return request.body, False
        except Exception:
            return b"", False

    # -- decisão --------------------------------------------------------
    def _is_auth_failure(self, request, response) -> bool:
        status = response.status_code
        if status in self.FAILURE_STATUS_ANYWHERE:
            return True
        return request.path in self.login_paths and status in self.FAILURE_STATUS_ON_LOGIN

    # -- gravação -------------------------------------------------------
    def _client_ip(self, request):
        if self.trust_proxy:
            xff = request.META.get("HTTP_X_FORWARDED_FOR")
            if xff:
                return xff.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")

    def _record(self, request, response, raw_body, truncated):
        ctype = request.META.get("CONTENT_TYPE", "")
        body = parse_and_redact_body(raw_body, ctype)

        identifier = ""
        if isinstance(body, dict):
            for f in IDENTIFIER_FIELDS:
                if isinstance(body.get(f), str):
                    identifier = body[f][:254]
                    break

        tenant = getattr(request, "tenant", None)  # definido por middleware de tenant anterior
        FailedAuthAttempt.objects.create(
            tenant_id=str(tenant.pk) if tenant is not None else None,
            identifier=identifier,
            method=request.method,
            path=request.path[:2048],
            query_string=redact_query_string(request.META.get("QUERY_STRING", "")),
            status_code=response.status_code,
            ip_address=self._client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:512],
            headers=safe_headers(request.META),
            body=body,
            body_truncated=truncated,
            request_id=request.META.get("HTTP_X_REQUEST_ID", "") or uuid.uuid4().hex,
        )

import logging
import uuid

from django.conf import settings

from .models import FailedAuthAttempt
from .redaction import parse_and_redact_body, redact_query_string, safe_headers

logger = logging.getLogger(__name__)

# Campos que podem conter o identificador informado pelo usuário
IDENTIFIER_FIELDS = ("email", "username", "login", "user", "usuario")


class FailedAuthLogMiddleware:
    """
    Registra tentativas de autenticação malsucedidas.

    Settings opcionais:
      AUTHLOG_LOGIN_PATHS    = ("/api/auth/login/",)  # rotas onde 400/403 também indicam falha
      AUTHLOG_MAX_BODY_BYTES = 16 * 1024
      AUTHLOG_TRUSTED_PROXY  = False  # True só se houver proxy reverso confiável
    """

    FAILURE_STATUS_ANYWHERE = {401}
    FAILURE_STATUS_ON_LOGIN = {400, 401, 403}

    def __init__(self, get_response):
        self.get_response = get_response
        self.login_paths = tuple(getattr(settings, "AUTHLOG_LOGIN_PATHS", ("/api/auth/login/",)))
        self.max_body = getattr(settings, "AUTHLOG_MAX_BODY_BYTES", 16 * 1024)
        self.trust_proxy = getattr(settings, "AUTHLOG_TRUSTED_PROXY", False)

    def __call__(self, request):
        # Lê o corpo ANTES da view (request.body fica em cache para a view usar).
        raw_body, truncated = self._capture_body(request)

        response = self.get_response(request)

        try:
            if self._is_auth_failure(request, response):
                self._record(request, response, raw_body, truncated)
        except Exception:
            # O log nunca pode derrubar ou alterar a resposta ao cliente.
            logger.exception("Falha ao registrar tentativa de autenticação malsucedida")
        return response

    # -- captura --------------------------------------------------------
    def _capture_body(self, request):
        if request.method not in ("POST", "PUT", "PATCH"):
            return b"", False
        ctype = request.META.get("CONTENT_TYPE", "").split(";")[0].strip().lower()
        if ctype not in ("application/json", "application/x-www-form-urlencoded"):
            return b"", False  # multipart/uploads: não lê, evita consumir stream
        try:
            length = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length > self.max_body:
            return b"", True  # grande demais: não carrega em memória
        try:
            return request.body, False
        except Exception:
            return b"", False

    # -- decisão --------------------------------------------------------
    def _is_auth_failure(self, request, response) -> bool:
        status = response.status_code
        if status in self.FAILURE_STATUS_ANYWHERE:
            return True
        return request.path in self.login_paths and status in self.FAILURE_STATUS_ON_LOGIN

    # -- gravação -------------------------------------------------------
    def _client_ip(self, request):
        if self.trust_proxy:
            xff = request.META.get("HTTP_X_FORWARDED_FOR")
            if xff:
                return xff.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")

    def _record(self, request, response, raw_body, truncated):
        ctype = request.META.get("CONTENT_TYPE", "")
        body = parse_and_redact_body(raw_body, ctype)

        identifier = ""
        if isinstance(body, dict):
            for f in IDENTIFIER_FIELDS:
                if isinstance(body.get(f), str):
                    identifier = body[f][:254]
                    break

        tenant = getattr(request, "tenant", None)  # definido por middleware de tenant anterior
        FailedAuthAttempt.objects.create(
            tenant_id=str(tenant.pk) if tenant is not None else None,
            identifier=identifier,
            method=request.method,
            path=request.path[:2048],
            query_string=redact_query_string(request.META.get("QUERY_STRING", "")),
            status_code=response.status_code,
            ip_address=self._client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:512],
            headers=safe_headers(request.META),
            body=body,
            body_truncated=truncated,
            request_id=request.META.get("HTTP_X_REQUEST_ID", "") or uuid.uuid4().hex,
        )

MIDDLEWARE = [
    # ... segurança, sessão, middleware que resolve o tenant (request.tenant) ...
    "authlog.middleware.FailedAuthLogMiddleware",
    # ... demais ...
]
AUTHLOG_LOGIN_PATHS = ("/api/auth/login/",)