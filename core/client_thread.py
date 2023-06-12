import hashlib
import socket
import sqlite3
import hmac
import structlog

from time import time
from threading import Thread
from core.exceptions import SecurityException

logger = structlog.get_logger()

BUFFER_SIZE = 1024
DATABASE_PATH = ""


class ClientThread(Thread):
    def __init__(self, client_socket: socket.socket):
        super().__init__()
        self.client_socket = client_socket

    def run(self) -> None:
        client_id = self.client_socket.recv(BUFFER_SIZE).decode()

        client_key = ""
        session_id = hmac.HMAC(client_key.encode(), str(int(time())), "sha1").hexdigest()

        user_id = self.client_socket.recv(BUFFER_SIZE).decode()

        db_con = sqlite3.connect(DATABASE_PATH)
        db_cursor = db_con.cursor()
        db_cursor.execute("SELECT client_key FROM clients WHERE client_id == ?", client_id)

        try:
            server_passwd_hash = ""
            user_access = ""

            self.client_socket.sendall(session_id.encode())

            client_hash_method = self.client_socket.recv(BUFFER_SIZE).decode()
            client_session_passwd = self.client_socket.recv(BUFFER_SIZE).decode()

            server_session_passwd = hashlib\
                .new(client_hash_method, (server_passwd_hash + session_id).encode())\
                .hexdigest()
            if server_session_passwd.upper() == client_session_passwd.upper():
                self.client_socket.sendall(str(user_access).encode())
            else:
                raise SecurityException("Mot de passe incorrect !")
        except KeyError:
            self.client_socket.sendall(b"-1")
        except SecurityException:
            self.client_socket.sendall(b"-2")
