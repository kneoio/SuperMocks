import socket
import threading
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('MockOracleServer')


class MockOracleServer:
    def __init__(self, host='0.0.0.0', port=1521):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False

    def parse_connection_string(self, data):
        try:
            desc_start = data.find(b'(DESCRIPTION=')
            if desc_start != -1:
                desc_bytes = data[desc_start:]
                desc_str = desc_bytes.decode('ascii', errors='ignore')
                logger.info("\n=== Connection Details ===")
                logger.info(f"Connection string: {desc_str}")
                logger.info("=====================\n")
        except Exception as e:
            logger.error(f"Error parsing connection string: {e}")

    def handle_client(self, client_socket, address):
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break

                logger.info(f"New connection attempt from {address}")
                self.parse_connection_string(data)

                response = b"ERROR: ORA-01017: invalid username/password; logon denied\n"
                client_socket.send(response)

        except Exception as e:
            logger.error(f"Error handling client {address}: {e}")
        finally:
            logger.info(f"Connection closed from {address}")
            client_socket.close()

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        logger.info(f"Mock Oracle server listening on {self.host}:{self.port}")

        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.start()
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")

    def stop(self):
        self.running = False
        self.server_socket.close()
        logger.info("Mock Oracle server stopped")


if __name__ == "__main__":
    server = MockOracleServer()
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.stop()