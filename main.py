import http.server  # Our http server handler for http requests
import json
import socketserver  # Establish the TCP Socket connections
import logging

PORT = 9000


class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        if path.startswith('/v1/permittedUseCases'):
            logging.info("/permittedUseCases request")
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'useCases': [{"useCase": "Activity"}]}).encode())
            return
        elif path.startswith('/iopiopiopipo'):
            self.send_response(441)
            self.end_headers()
            return
        else:
            self.wfile.write("<b>The handler not found</b>".encode())
            self.send_response(404)
            self.end_headers()
            return

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])  # <--- Gets the size of data
        post_data = self.rfile.read(content_length)  # <--- Gets the data itself
        logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                     str(self.path), str(self.headers), post_data.decode('utf-8'))

        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))


Handler = MyHttpRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("Http Server Serving at port", PORT)
    httpd.serve_forever()
