import json
import logging
import os
import urllib.error
import urllib.request
from typing import Callable, Iterable, Optional, Tuple


logger = logging.getLogger(__name__)

StartResponse = Callable[[str, list], Callable]
WSGIApp = Callable[[dict, StartResponse], Iterable[bytes]]


class BillingServiceError(Exception):
    """Erro ao consultar o serviço de faturamento."""


class InactiveSubscription(Exception):
    """A empresa não possui uma assinatura ativa."""


class BillingClient:
    """
    Cliente para o serviço externo de faturamento.

    A URL é configurada pela aplicação, e não pelo cliente,
    reduzindo risco de SSRF.
    """

    def __init__(
        self,
        base_url: str,
        api_token: str,
        timeout: float = 3.0,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("O serviço de faturamento deve utilizar HTTPS")

        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout

    def is_subscription_active(self, tenant_id: str) -> bool:
        """
        Consulta o status da assinatura de um tenant.

        Espera uma resposta JSON semelhante a:
        {
            "active": true
        }
        """

        # tenant_id não deve ser usado para construir URLs arbitrárias.
        # Neste exemplo, usamos URL encoding para evitar problemas com
        # caracteres especiais.
        from urllib.parse import quote

        encoded_tenant_id = quote(tenant_id, safe="")

        url = f"{self.base_url}/v1/subscriptions/{encoded_tenant_id}"

        request = urllib.request.Request(
            url=url,
            method="GET",
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Accept": "application/json",
                "User-Agent": "saas-backend/1.0",
            },
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:

                if response.status != 200:
                    raise BillingServiceError(
                        f"Serviço de faturamento retornou HTTP {response.status}"
                    )

                # Limita o tamanho máximo da resposta para evitar consumo
                # excessivo de memória.
                body = response.read(16 * 1024)

        except (urllib.error.URLError, TimeoutError) as exc:
            raise BillingServiceError(
                "Não foi possível consultar o serviço de faturamento"
            ) from exc

        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BillingServiceError(
                "Resposta inválida do serviço de faturamento"
            ) from exc

        active = payload.get("active")

        if not isinstance(active, bool):
            raise BillingServiceError(
                "Resposta do serviço de faturamento possui formato inválido"
            )

        return active


class SubscriptionMiddleware:
    """
    Middleware WSGI responsável por verificar a assinatura do tenant.

    Pré-requisito:
        Um middleware de autenticação anterior deve popular:

            environ["saas.user"]

        com algo semelhante a:

            {
                "id": "user-123",
                "tenant_id": "tenant-456"
            }

    O cliente nunca deve conseguir definir diretamente esse valor.
    """

    def __init__(
        self,
        app: WSGIApp,
        billing_client: BillingClient,
    ) -> None:
        self.app = app
        self.billing_client = billing_client

    def __call__(
        self,
        environ: dict,
        start_response: StartResponse,
    ) -> Iterable[bytes]:

        user = environ.get("saas.user")

        # Ausência de identidade autenticada => negar acesso.
        if not isinstance(user, dict):
            return self._error_response(
                start_response,
                "401 Unauthorized",
                "Autenticação necessária",
            )

        tenant_id = user.get("tenant_id")

        # Não aceitar tenant_id diretamente de headers, query string,
        # cookies ou corpo da requisição.
        if not isinstance(tenant_id, str) or not tenant_id:
            logger.warning(
                "Usuário autenticado sem tenant_id"
            )

            return self._error_response(
                start_response,
                "403 Forbidden",
                "Tenant não identificado",
            )

        # Validação básica de tamanho.
        # A identidade real deve idealmente ser validada também
        # pelo componente de autenticação/autorização.
        if len(tenant_id) > 128:
            return self._error_response(
                start_response,
                "403 Forbidden",
                "Tenant inválido",
            )

        try:
            active = self.billing_client.is_subscription_active(
                tenant_id
            )

        except BillingServiceError:
            # Fail closed:
            # sem confirmação do billing, não liberamos acesso.
            logger.error(
                "Falha ao verificar assinatura do tenant"
            )

            return self._error_response(
                start_response,
                "503 Service Unavailable",
                "Não foi possível verificar a assinatura",
            )

        if not active:
            return self._error_response(
                start_response,
                "402 Payment Required",
                "Assinatura inativa",
            )

        # Assinatura ativa: continua para a aplicação.
        return self.app(environ, start_response)

    @staticmethod
    def _error_response(
        start_response: StartResponse,
        status: str,
        message: str,
    ) -> Iterable[bytes]:

        body = json.dumps(
            {
                "error": message,
            },
            ensure_ascii=False,
        ).encode("utf-8")

        headers = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
        ]

        start_response(status, headers)

        return [body]


def create_application(app: WSGIApp) -> WSGIApp:
    """
    Configuração do middleware.

    As credenciais são obtidas do ambiente/secret manager,
    nunca do código-fonte.
    """

    billing_url = os.environ.get("BILLING_SERVICE_URL")
    billing_token = os.environ.get("BILLING_SERVICE_TOKEN")

    if not billing_url:
        raise RuntimeError(
            "BILLING_SERVICE_URL não configurada"
        )

    if not billing_token:
        raise RuntimeError(
            "BILLING_SERVICE_TOKEN não configurado"
        )

    billing_client = BillingClient(
        base_url=billing_url,
        api_token=billing_token,
        timeout=3.0,
    )

    return SubscriptionMiddleware(
        app=app,
        billing_client=billing_client,
    )
