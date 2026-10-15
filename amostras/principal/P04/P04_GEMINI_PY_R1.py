import re

class DynamicCORSMiddleware:
    """
    Middleware WSGI para gerenciamento de CORS em API pública SaaS Multilocatária.

    Permite requisições de origens permitidas enviando credenciais de sessão (cookies/headers de auth).
    """

    def __init__(self, app, allowed_origins_exact=None, allowed_origin_regexes=None):
        self.app = app
        # Domínios fixos permitidos (ex: painel administrativo, apps oficiais)
        self.allowed_origins_exact = set(allowed_origins_exact or [
            "https://app.minhaplataformasaas.com",
            "https://admin.minhaplataformasaas.com"
        ])
        # Padrões Regex para subdomínios de clientes (ex: https://empresaA.minhaplataformasaas.com)
        self.allowed_origin_regexes = [
            re.compile(pattern) for pattern in (allowed_origin_regexes or [
                r"^https://[a-zA-Z0-9-]+\.minhaplataformasaas\.com$"
            ])
        ]

    def is_origin_allowed(self, origin: str) -> bool:
        """Valida se a origem da requisição é permitida."""
        if not origin:
            return False

        if origin in self.allowed_origins_exact:
            return True

        # Validação via regex para subdomínios dinâmicos dos clientes
        for regex in self.allowed_origin_regexes:
            if regex.match(origin):
                return True

        # Opcional: Consultar cache de banco de dados/Redis para domínios customizados
        # ex: return self.check_custom_domain_in_cache(origin)

        return False

    def __call__(self, environ, start_response):
        origin = environ.get('HTTP_ORIGIN')
        request_method = environ.get('REQUEST_METHOD')

        # Requisição Preflight (OPTIONS)
        if request_method == 'OPTIONS':
            headers = []
            if origin and self.is_origin_allowed(origin):
                headers = [
                    ('Access-Control-Allow-Origin', origin),
                    ('Access-Control-Allow-Credentials', 'true'),
                    ('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS'),
                    ('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Tenant-ID, X-Requested-With'),
                    ('Access-Control-Max-Age', '86400'),  # Cache da preflight por 24h
                    ('Vary', 'Origin'),
                    ('Content-Type', 'text/plain; charset=utf-8'),
                    ('Content-Length', '0')
                ]
                start_response('204 No Content', headers)
                return [b'']
            else:
                # Origem não permitida no preflight
                start_response('403 Forbidden', [('Content-Type', 'text/plain; charset=utf-8')])
                return [b'Origin not allowed']

        # Requisições normais (GET, POST, PUT, DELETE, etc.)
        def custom_start_response(status, headers, exc_info=None):
            if origin and self.is_origin_allowed(origin):
                headers.append(('Access-Control-Allow-Origin', origin))
                headers.append(('Access-Control-Allow-Credentials', 'true'))
                headers.append(('Access-Control-Expose-Headers', 'X-Tenant-ID, X-Total-Count'))
                headers.append(('Vary', 'Origin'))

            return start_response(status, headers, exc_info)

        return self.app(environ, custom_start_response)