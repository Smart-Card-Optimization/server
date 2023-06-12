import hmac
import time


def hotp(key: bytes, message: bytes) -> str:
    mac = hmac.HMAC(key, message, "sha1").hexdigest()
    mac = int(mac, base=16)
    return str(mac % 10 ** 6).zfill(6)


def totp(key: bytes, interval: int = 30) -> str:
    return hotp(key, str(int(time.time()) // interval).encode())
