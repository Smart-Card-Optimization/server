import sqlite3
import socket
import ssl
import structlog
import threading

from core.client_thread import ClientThread

logger = structlog.get_logger()


class Server:
    def __init__(self, sock: socket.socket = None):
        if sock is None:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            logger.debug("Default IPv4 TCP socket created.")
        else:
            self.server_socket = sock

    def start(self, server_address: str, server_port: int):
        self.server_socket.bind((server_address, server_port))
        logger.debug("Socket binded to port %d.", server_port)

        self.server_socket.listen()
        logger.info("Server listening on port %d...", server_port)

    def accept(self):
        client_socket, addr = self.server_socket.accept()
        logger.debug("Connection created to %s on port %d.", addr[0], addr[1])

        client_thread = ClientThread(client_socket)
        logger.debug("Thread created to handle the connection.")
        client_thread.start()


def main():
    server = Server()
    server.start("localhost", 55555)

    while True:
        server.accept()


if __name__ == "__main__":
    main()
