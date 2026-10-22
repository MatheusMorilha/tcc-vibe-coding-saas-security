from typing import Callable, Iterable, List, Optional, Tuple


class CORSMiddleware:
    """
    Middleware WSGI para a API pública de uma aplicação SaaS
    multilocatária.

    - Permite credenciais de sessão (cookies).
    - Nunca utiliza Access-Control-Allow-Origin: *.
    - Valida a origem antes de permitir CORS.
    - Responde corretamente a requisições preflight (OPTIONS).
    """

    def __init__(
        self,
        app: Callable,
        allowed_origins: Optional[List[str]] = None,
    )-> None:
        self.app= app
        self.allowed_origins= set(allowed_origins or [])

    def __call__(self, environ, start_response):
        origin= environ.get("HTTP_ORIGIN")

        # Requisição sem Origin: não é uma requisição CORS.
        if not origin:
            return self.app(environ, start_response)

        # Nunca permitir wildcard quando credenciais são utilizadas.
        if originnot in self.allowed_origins:
            return self.app(environ, start_response)

        method= environ.get("REQUEST_METHOD","GET").upper()

        if method== "OPTIONS":
            return self._preflight(environ, start_response, origin)

        return self._request(environ, start_response, origin)

    def _headers(self, origin: str)-> List[Tuple[str, str]]:
        return [
            ("Access-Control-Allow-Origin", origin),
            ("Access-Control-Allow-Credentials", "true"),
            (
                "Access-Control-Expose-Headers",
                "Content-Length, Content-Type, X-Request-ID",
            ),
            ("Vary", "Origin"),
        ]

    def _request(self, environ, start_response, origin: str):
        def cors_start_response(status, headers, exc_info=None):
            headers= list(headers)
            headers.extend(self._headers(origin))
            return start_response(status, headers, exc_info)

        return self.app(environ, cors_start_response)

    def _preflight(self, environ, start_response, origin: str):
        requested_method= environ.get("HTTP_ACCESS_CONTROL_REQUEST_METHOD")
        requested_headers= environ.get("HTTP_ACCESS_CONTROL_REQUEST_HEADERS","")

        allowed_methods= {
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }

        if requested_method and requested_method.upper() not in allowed_methods:
            start_response(
                "403 Forbidden",
                [
                    ("Content-Type","text/plain; charset=utf-8"),
                    ("Content-Length","0"),
                ],
            )
            return [b""]

        response_headers= self._headers(origin)
        response_headers.extend(
            [
                (
                    "Access-Control-Allow-Methods",
                    ", ".join(sorted(allowed_methods)),
                ),
                (
                    "Access-Control-Allow-Headers",
                    requested_headers,
                ),
                ("Access-Control-Max-Age","600"),
                ("Content-Length","0"),
            ]
        )

        start_response("204 No Content", response_headers)
        return [b""]