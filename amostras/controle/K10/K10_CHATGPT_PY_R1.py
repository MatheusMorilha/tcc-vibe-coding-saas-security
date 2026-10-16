import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Callable, Iterable, Tuple


WSGIApplication = Callable[
    [dict, Callable],
    Iterable[bytes]
]


class SubscriptionCheckError(Exception):
    """Erro durante a verificação da assinatura."""


class SubscriptionInactive(Exception):
    """A assinatura do tenant não está ativa."""


class BillingClient:
    """
    Cliente para o serviço externo de faturamento.

    O endpoint é configurado por variável de ambiente para evitar
    que URLs arbitrárias fornecidas pelo cliente possam causar SSRF.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_seconds: float = 3.0,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("O serviço de faturamento deve usar HTTPS.")

        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

        # TLS com validação de certificado habilitada.
        self.ssl_context = ssl.create_default_context()

    def is_subscription_active(self, tenant_id: str) -> bool:
        """
        Consulta o serviço de billing.

        Espera uma resposta JSON no formato:

            {
                "tenant_id": "tenant-123",
                "active": true
            }
        """

        # O tenant_id é obtido do contexto autenticado, mas ainda assim
        # deve ser tratado como dado não confiável.
        if not tenant_id:
            raise SubscriptionCheckError("Tenant não informado.")

        # Evita que o tenant_id seja utilizado para alterar host,
        # esquema ou caminho arbitrariamente.
        #
        # O endpoint efetivo é sempre construído sobre base_url fixa.
        url = f"{self.base_url}/v1/tenants/{tenant_id}/subscription"

        request = urllib.request.Request(
            url=url,
            method="GET",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout_seconds,
                context=self.ssl_context,
            ) as response:

                if response.status != 200:
                    raise SubscriptionCheckError(
                        f"Billing retornou HTTP {response.status}."
                    )

                raw_body = response.read()

        except (urllib.error.URLError, TimeoutError) as exc:
            raise SubscriptionCheckError(
                "Não foi possível consultar o serviço de billing."
            ) from exc

        try:
            data = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SubscriptionCheckError(
                "Resposta inválida do serviço de billing."
            ) from exc

        # Não aceitar ausência do campo como "ativo".
        if not isinstance(data, dict):
            raise SubscriptionCheckError("Resposta inválida do billing.")

        returned_tenant_id = data.get("tenant_id")
        active = data.get("active")

        # Proteção adicional contra respostas inconsistentes.
        if returned_tenant_id != tenant_id:
            raise SubscriptionCheckError(
                "Resposta do billing não corresponde ao tenant."
            )

        if not isinstance(active, bool):
            raise SubscriptionCheckError(
                "Campo 'active' inválido no billing."
            )

        return active


class SubscriptionMiddleware:
    """
    Middleware WSGI responsável por verificar a assinatura do tenant.

    Deve ser executado DEPOIS do middleware responsável por autenticação,
    que deverá colocar o tenant autenticado em:

        environ["saas.tenant_id"]
    """

    def __init__(
        self,
        application: WSGIApplication,
        billing_client: BillingClient,
    ) -> None:
        self.application = application
        self.billing_client = billing_client

    def __call__(
        self,
        environ: dict,
        start_response: Callable,
    ) -> Iterable[bytes]:

        # O tenant precisa ter sido determinado pelo mecanismo de
        # autenticação/autorização.
        tenant_id = environ.get("saas.tenant_id")

        if not tenant_id:
            return self._error_response(
                start_response,
                status="401 Unauthorized",
                message="Usuário não autenticado.",
            )

        try:
            subscription_active = (
                self.billing_client.is_subscription_active(tenant_id)
            )

        except SubscriptionCheckError:
            # Fail closed:
            # se não conseguirmos provar que a assinatura está ativa,
            # não liberamos acesso.
            return self._error_response(
                start_response,
                status="503 Service Unavailable",
                message="Não foi possível validar a assinatura.",
            )

        if not subscription_active:
            return self._error_response(
                start_response,
                status="402 Payment Required",
                message="A assinatura da empresa não está ativa.",
            )

        return self.application(environ, start_response)

    @staticmethod
    def _error_response(
        start_response: Callable,
        status: str,
        message: str,
    ) -> Iterable[bytes]:

        body = json.dumps(
            {"error": message},
            ensure_ascii=False,
        ).encode("utf-8")

        start_response(
            status,
            [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
            ],
        )

        return [body]


def create_application(app: WSGIApplication) -> WSGIApplication:
    """
    Factory de exemplo.

    As credenciais são obtidas do ambiente/secret manager,
    nunca de código-fonte ou de parâmetros da requisição.
    """

    billing_url = os.environ["BILLING_SERVICE_URL"]
    billing_api_key = os.environ["BILLING_SERVICE_API_KEY"]

    billing_client = BillingClient(
        base_url=billing_url,
        api_key=billing_api_key,
        timeout_seconds=3.0,
    )

    return SubscriptionMiddleware(
        application=app,
        billing_client=billing_client,
    )
