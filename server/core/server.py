import argparse
import socket
import tomllib

import structlog

from server.core.client_thread import ClientThread

logger = structlog.get_logger()


class Server:
    SERVER_ADDRESS = ""
    SERVER_PORT = 0
    DATABASE_PATH = ""

    def __init__(self, config: dict, sock: socket.socket = None):
        if sock is None:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            logger.debug("Default IPv4 TCP socket created.")
        else:
            self.server_socket = sock

        self.populate_params(config)

    def __call__(self, *args, **kwargs):
        self.server_socket.bind((Server.SERVER_ADDRESS, Server.SERVER_PORT))
        logger.debug("Socket binded to port %d.", Server.SERVER_PORT)

        self.server_socket.listen()
        logger.info("Server listening on port %d...", Server.SERVER_PORT)

    def accept(self):
        client_socket, addr = self.server_socket.accept()
        logger.debug("Connection created to %s on port %d.", addr[0], addr[1])

        client_thread = ClientThread(client_socket, Server.DATABASE_PATH)
        logger.debug("Thread created to handle the connection.")
        client_thread.start()

    def populate_params(self, config: dict):
        Server.SERVER_ADDRESS = config["server"]["ip"]
        Server.SERVER_PORT = config["server"]["port"]
        Server.DATABASE_PATH = config["db"]["path"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config",
                        default="./config.toml",
                        metavar="PATH",
                        help="Le chemin vers le fichier de configuration")

    args = parser.parse_args()

    with open(args.config, "rb") as f:
        config = tomllib.load(f)
        logger.debug("Configuration loaded.")

    server = Server(config)
    server()

    while True:
        server.accept()


if __name__ == "__main__":
    main()
