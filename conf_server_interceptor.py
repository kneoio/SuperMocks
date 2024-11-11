import os
import re
import socket
import ssl
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from utils.logging import logger

LOG_PATTERN = os.getenv("LOG_PATTERN", "config")

class ProxyHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        try:
            host, port = self.path.split(':')
            port = int(port)

            logger.info(f"\n{'=' * 50}")
            logger.info(f"CONNECT request for: {host}:{port}")
            logger.info(f"Headers: {dict(self.headers)}")

            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.connect((host, port))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs(purpose=ssl.Purpose.SERVER_AUTH)

            target_ssl = context.wrap_socket(
                target_sock,
                server_hostname=host
            )
            self.send_response(200, 'Connection Established')
            self.end_headers()
            self.forward_data(self.connection, target_ssl, host)

        except Exception as e:
            logger.error(f"Error handling CONNECT: {e}")
            if not self.wfile.closed:
                self.send_error(502)
            return

    def forward_data(self, client_socket, server_socket, host):
        def pump(source, destination, direction):
            try:
                buffer = bytearray()
                while True:
                    try:
                        data = source.recv(8192)
                        if not data:
                            break

                        buffer.extend(data)

                        while True:
                            header_end = buffer.find(b'\r\n\r\n')
                            if header_end == -1:
                                break

                            headers = buffer[:header_end].decode('utf-8', errors='ignore')
                            content_length = 0
                            for line in headers.split('\r\n'):
                                if line.lower().startswith('content-length:'):
                                    content_length = int(line.split(':')[1].strip())
                                    break

                            total_length = header_end + 4 + content_length
                            if len(buffer) >= total_length:
                                message = buffer[:total_length]
                                buffer = buffer[total_length:]

                                try:
                                    decoded = message.decode('utf-8', errors='ignore')
                                    if re.search(LOG_PATTERN, decoded, re.IGNORECASE):
                                        logger.info(f"\n{'=' * 50}")
                                        logger.info(f"Direction: {direction}")
                                        logger.info(f"Host: {host}")
                                        logger.info(f"Message:\n{decoded}")
                                        logger.info(f"{'=' * 50}\n")
                                except Exception as e:
                                    logger.error(f"Error decoding message: {e}")
                            else:
                                break

                        destination.sendall(data)
                    except socket.error:
                        break
            except Exception as e:
                logger.error(f"Error in pump {direction}: {e}")
            finally:
                try:
                    source.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    destination.shutdown(socket.SHUT_RDWR)
                except:
                    pass

        # Create threads for bidirectional forwarding
        client_to_server = threading.Thread(
            target=pump,
            args=(client_socket, server_socket, "Client → Server")
        )
        server_to_client = threading.Thread(
            target=pump,
            args=(server_socket, client_socket, "Server → Client")
        )

        # Start both threads
        client_to_server.start()
        server_to_client.start()

        # Wait for both threads to finish
        client_to_server.join()
        server_to_client.join()


def list_certificates():
    paths = ssl.get_default_verify_paths()
    cert_paths = [paths.cafile] if paths.cafile else []
    if paths.capath:
        cert_paths.extend([os.path.join(paths.capath, f) for f in os.listdir(paths.capath)])

    for cert_path in cert_paths:
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()

                # Find PEM certificate blocks
                pem_certs = re.findall(b'(-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----)', cert_data,
                                       re.DOTALL)

                for pem_cert in pem_certs:
                    try:
                        cert = x509.load_pem_x509_certificate(pem_cert, default_backend())
                        logger.info(f"Issuer: {cert.issuer}")
                    except Exception as e:
                        logger.error(f"Error parsing a certificate in {cert_path}: {e}")
        except Exception as e:
            logger.error(f"Error reading certificate from {cert_path}: {e}")


def run_proxy(port=8977):
    logger.info("Listing system SSL certificates...")
    list_certificates()
    server = HTTPServer(('', port), ProxyHandler)
    logger.info(f"Starting proxy server on port {port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down proxy")
        server.server_close()


if __name__ == '__main__':
    run_proxy()
