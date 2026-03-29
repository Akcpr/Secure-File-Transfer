import http.server
import socketserver

PORT = 8000

ALLOWED_FILES = {"/server.html", "/certificate.pem", "/"}

class RestrictedHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ALLOWED_FILES:
            if self.path == "/":
                self.path = "/server.html"
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        else:
            self.send_error(403, "Forbidden: You are not allowed to access this resource.")

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), RestrictedHandler) as httpd:
        print(f"Serving at http://localhost:{PORT}/server.html")
        httpd.serve_forever()