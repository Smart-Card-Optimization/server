import hashlib
import socket
import hmac
from time import time
from threading import Thread

import structlog

from basket.data.db import Database
from server.core.exceptions import SecurityException

logger = structlog.get_logger()


class ClientThread(Thread):
    BUFFER_SIZE = 1024

    def __init__(self, client_socket: socket.socket, db_path: str):
        super().__init__()
        self.client_socket = client_socket

        self.db_path = db_path

    def run(self) -> None:
        db = Database(self.db_path)
        logger.debug("Link to database created to %s.", self.db_path)

        route = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()

        match route:
            case "2":
                pass
            case "3":
                self.manage_clients(db)
            case _:
                self.access(db)

    def access(self, db: Database):
        client_id = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()

        client_key = db.get_client_key_by_id(int(client_id))
        session_id = hmac.HMAC(client_key.encode(), str(int(time())), "sha1").hexdigest()

        user_id = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()

        try:
            server_passwd_hash = db.get_passwd_hash_by_id(int(user_id))
            user_access = db.get_user_access_by_id(int(user_id))

            self.client_socket.sendall(session_id.encode())

            client_hash_method = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()
            client_session_passwd = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()

            server_session_passwd = hashlib \
                .new(client_hash_method, (server_passwd_hash + session_id).encode()) \
                .hexdigest()
            if server_session_passwd.upper() == client_session_passwd.upper():
                self.client_socket.sendall(str(user_access).encode())
            else:
                raise SecurityException("Mot de passe incorrect !")
        except KeyError:
            self.client_socket.sendall(b"-1")
        except SecurityException:
            self.client_socket.sendall(b"-2")

    def manage_users(self, db: Database):
        client_id = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()

        client_key = db.get_client_key_by_id(int(client_id))
        session_id = hmac.HMAC(client_key.encode(), str(int(time())), "sha1").hexdigest()

        user_id = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()

        try:
            server_passwd_hash = db.get_passwd_hash_by_id(int(user_id))
            user_access = db.get_user_access_by_id(int(user_id))

            self.client_socket.sendall(session_id.encode())

            client_hash_method = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()
            client_session_passwd = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()

            server_session_passwd = hashlib \
                .new(client_hash_method, (server_passwd_hash + session_id).encode()) \
                .hexdigest()
            if server_session_passwd.upper() == client_session_passwd.upper():
                self.client_socket.sendall(str(user_access).encode())
            else:
                raise SecurityException("Mot de passe incorrect !")
        except KeyError:
            self.client_socket.sendall(b"-1")
        except SecurityException:
            self.client_socket.sendall(b"-2")

    def manage_clients(self, db: Database):
        client_id = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()
        try:
            is_client_manager = db.

        client_key = db.get_client_key_by_id(int(client_id))
        session_id = hmac.HMAC(client_key.encode(), str(int(time())), "sha1").hexdigest()

        user_id = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()

        try:
            server_passwd_hash = db.get_passwd_hash_by_id(int(user_id))
            user_access = db.get_user_access_by_id(int(user_id))

            self.client_socket.sendall(session_id.encode())

            client_hash_method = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()
            client_session_passwd = self.client_socket.recv(ClientThread.BUFFER_SIZE).decode()

            server_session_passwd = hashlib \
                .new(client_hash_method, (server_passwd_hash + session_id).encode()) \
                .hexdigest()
            if server_session_passwd.upper() == client_session_passwd.upper():
                self.client_socket.sendall(str(user_access).encode())
            else:
                raise SecurityException("Mot de passe incorrect !")
        except KeyError:
            self.client_socket.sendall(b"-1")
        except SecurityException:
            self.client_socket.sendall(b"-2")
