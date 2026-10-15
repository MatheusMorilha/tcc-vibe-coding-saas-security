from typing import Callable, Iterable

ALLOWED_ORIGINS= {
    "https://app.cliente-a.com",
    "https://app.cliente-b.com",
}

ALLOW_METHODS= "GET, POST, PUT, PATCH, DELETE, OPTIONS"
ALLOW_HEADERS= "Content-Type, Authorization, X-CSRF-Token"
EXPOSE_HEADERS= "Content-Length, Content-Range"


class CORSMiddleware:
    """
    Middleware WSGI para API pública com suporte a credenciais de sessão.

    Importante:
    - Nunca usa Access-Control-Allow-Origin: *
      quando credenciais estão habilitadas.
    - Somente origens previamente autorizadas recebem acesso.
    - OPTIONS é tratado como preflight.
    """

    def __init__(
        self,
        app: Callable,
        allowed_origins: Iterable[str],
    )-> None:
        self.app= app
        self.allowed_origins= frozenset(allowed_origins)

    def __call__(self, environ, start_response):
        origin= environ.get("HTTP_ORIGIN")

        if originnot in self.allowed_origins:
            return self.app(environ, start_response)

        method= environ.get("REQUEST_METHOD","").upper()

        if method== "OPTIONS":
            def preflight_response(status, headers, exc_info=None):
                headers= self._headers(headers, origin)
                start_response("204 No Content", headers, exc_info)
                return []

            return preflight_response

        def response(status, headers, exc_info=None):
            headers= self._headers(headers, origin)
            return start_response(status, headers, exc_info)

        return self.app(environ, response)

    @staticmethod
    def _headers(headers, origin):
        headers= list(headers)

        headers.extend([
            ("Access-Control-Allow-Origin", origin),
            ("Access-Control-Allow-Credentials","true"),
            ("Access-Control-Allow-Methods", ALLOW_METHODS),
            ("Access-Control-Allow-Headers", ALLOW_HEADERS),
            ("Access-Control-Expose-Headers", EXPOSE_HEADERS),
            ("Vary","Origin"),
        ])

        return headers


# Exemplo de composição:
#
# application = CORSMiddleware(
#     application,
#     allowed_origins=ALLOWED_ORIGINS,
# )