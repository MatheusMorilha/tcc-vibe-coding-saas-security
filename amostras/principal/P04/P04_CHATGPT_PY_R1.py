
class CORSMiddleware:
    def __init__(
        self,
        app,
        allowed_origins,
        allowed_methods=None,
        allowed_headers=None,
    ):
        self.app = app
        self.allowed_origins = set(allowed_origins)

        self.allowed_methods = allowed_methods or [
            "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        ]

        self.allowed_headers = allowed_headers or [
            "Content-Type",
            "Authorization",
            "X-CSRF-Token",
        ]

    def __call__(self, environ, start_response):
        origin = environ.get("HTTP_ORIGIN")
        method = environ.get("REQUEST_METHOD", "GET")

        # A resposta varia conforme a origem recebida.
        def add_vary_origin(headers):
            for index, (key, value) in enumerate(headers):
                if key.lower() == "vary":
                    values = {
                        item.strip().lower()
                        for item in value.split(",")
                    }
                    if "origin" not in values and "*" not in values:
                        headers[index] = (key, value + ", Origin")
                    return

            headers.append(("Vary", "Origin"))

        # Responde ao preflight somente para origens permitidas.
        if method == "OPTIONS" and origin in self.allowed_origins:
            requested_method = environ.get(
                "HTTP_ACCESS_CONTROL_REQUEST_METHOD", ""
            )
            requested_headers = [
                item.strip().lower()
                for item in environ.get(
                    "HTTP_ACCESS_CONTROL_REQUEST_HEADERS", ""
                ).split(",")
                if item.strip()
            ]

            allowed_methods = {
                item.upper() for item in self.allowed_methods
            }
            allowed_headers = {
                item.lower() for item in self.allowed_headers
            }

            if (
                requested_method.upper() not in allowed_methods
                or not set(requested_headers).issubset(allowed_headers)
            ):
                response = Response(status=403)
                return response(environ, start_response)

            response = Response(status=204)
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = ", ".join(
                self.allowed_methods
            )
            response.headers["Access-Control-Allow-Headers"] = ", ".join(
                self.allowed_headers
            )
            response.headers["Access-Control-Max-Age"] = "600"
            response.headers["Vary"] = (
                "Origin, Access-Control-Request-Method, "
                "Access-Control-Request-Headers"
            )

            return response(environ, start_response)

        def cors_start_response(status, headers, exc_info=None):
            headers = list(headers)
            add_vary_origin(headers)

            if origin in self.allowed_origins:
                headers.extend([
                    ("Access-Control-Allow-Origin", origin),
                    ("Access-Control-Allow-Credentials", "true"),
                ])

            return start_response(status, headers, exc_info)

        return self.app(environ, cors_start_response)


app = Flask(__name__)

# Origens confiáveis das aplicações frontend.
ALLOWED_ORIGINS = [
    "https://app.empresa-a.com",
    "https://app.empresa-b.com",
]

# Registre o middleware antes de atender às requisições.
app.wsgi_app = CORSMiddleware(
    app.wsgi_app,
    allowed_origins=ALLOWED_ORIGINS,
)


@app.get("/api/session")
def get_session():
    # Exemplo: a autenticação real deve validar a sessão.
    return jsonify({"message": "Endpoint acessível via CORS"})


if __name__ == "__main__":
    app.run(debug=False)
