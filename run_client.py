import sys
from client.client import Client


if __name__ == '__main__':
    client = Client()
    client.start("127.0.0.1")