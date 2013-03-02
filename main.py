# coding=utf-8
import socket
from icap import ICAP

def main():
    server = socket.socket()
    server.bind(('0.0.0.0', 12345))
    server.listen(5)
    (sock, address) = server.accept()
    try:
        sock.settimeout(30)

        i = ICAP()

        close_now = False
        while not close_now:
            data = sock.recv(4096)
            if not data:
                break
            for (resp, close_now) in i.parse(data):
                if resp:
                    sock.sendall(resp)
                # if close_now:
                #     break
    finally:
        sock.close()

if __name__ == '__main__':
    main()