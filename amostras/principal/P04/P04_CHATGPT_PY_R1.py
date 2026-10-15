from typing import Callable, Iterable, Tuple


class CORSMiddleware:
    """
    Middleware WSGI para a API pública.

    Permite:
      - requisições cross-origin;
      - credenciais (cookies de sessão);
      - preflight OPTIONS;
      - lista explícita de origens autorizadas.

    Não utiliza Access-Control-Allow-Origin: * porque a API
    aceita credenciais de sessão.
    """

    def __init__(
        self,
        app: Callable,
        allowed_origins: Iterable[str],
        allowed_methods: Iterable[str] = (
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
        ),
        allowed_headers: Iterable[str] = (
            "Content-Type",
            "Authorization",
            "X-CSRF-Token",
        ),
        expose_headers: Iterable[str] = (),
        max_age: int = 600,
    ):
        self.app= app
        self.allowed_origins= {
            origin.rstrip("/")
            for originin allowed_origins
        }

        self.allowed_methods= ", ".join(allowed_methods)
        self.allowed_headers= ", ".join(allowed_headers)
        self.expose_headers= ", ".join(expose_headers)
        self.max_age= str(max_age)

    def __call__(self, environ, start_response):
        origin= environ.get("HTTP_ORIGIN")

        # Requisição sem Origin:
        # normalmente é uma requisição same-origin, servidor-servidor
        # ou outro cliente que não utiliza o mecanismo CORS.
        if not origin:
            return self.app(environ, start_response)

        origin= origin.rstrip("/")

        # Origin não autorizada: não adicionamos cabeçalhos CORS.
        if originnot in self.allowed_origins:
            return self.app(environ, start_response)

        method= environ.get("REQUEST_METHOD","").upper()

        # Preflight CORS.
        if method== "OPTIONS":
            return self._preflight_response(
                origin,
                start_response,
            )

        def cors_start_response(
            status: str,
            headers: list[Tuple[str, str]],
            exc_info=None,
        ):
            headers= list(headers)

            headers.extend(
                [
                    ("Access-Control-Allow-Origin", origin),
                    ("Access-Control-Allow-Credentials","true"),
                    ("Vary","Origin"),
                ]
            )

            if self.expose_headers:
                headers.append(
                    (
                        "Access-Control-Expose-Headers",
                        self.expose_headers,
                    )
                )

            return start_response(
                status,
                headers,
                exc_info,
            )

        return self.app(
            environ,
            cors_start_response,
        )

    def _preflight_response(self, origin, start_response):
        headers= [
            ("Access-Control-Allow-Origin", origin),
            ("Access-Control-Allow-Credentials", "true"),
            ("Access-Control-Allow-Methods", self.allowed_methods),
            ("Access-Control-Allow-Headers", self.allowed_headers),
            ("Access-Control-Max-Age", self.max_age),
            ("Vary", "Origin"),
        ]

        start_response(
            "204 No Content",
            headers,
        )

        return [b""]