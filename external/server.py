import http.server
import ssl


def get_ssl_context(certfile, keyfile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(certfile, keyfile)
    context.set_ciphers("@SECLEVEL=1:ALL")
    return context


class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        post_data = bytes.decode(self.rfile.read(content_length))
        post_data = f"Received data:\n{post_data}\nNo more data."
        self.send_response(200)
        post_bytes = str.encode(post_data)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-length", len(post_bytes))
        self.end_headers()
        self.wfile.write(post_bytes)


server_address = ("0.0.0.0", 8001)
httpd = http.server.HTTPServer(server_address, MyHandler)

context = get_ssl_context("./cert.pem", "./private.key")
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

httpd.serve_forever()
