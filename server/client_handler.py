import logging
import socket
import ssl
import multiprocessing as mp
import sys

from shared.communication_protocol.transmission import recv_packet, send_packet
from shared.communication_protocol.packet_builder import build_packet
from shared.communication_protocol.packet_analyzer import PacketInfo
from shared.utils import sock_name
from shared.communication_protocol.communication_errors import TransmissionProtocolError, PacketStructureError, \
    PacketContentsError


class ClientHandler:
    def __init__(self, client_skt: socket.socket, record_tls_secrets: bool):
        self.socket: socket.socket | ssl.SSLSocket = client_skt
        self.name = sock_name(self.socket)

        self.console_logger = logging.getLogger("server_console")
        self.console_logger.setLevel(logging.INFO)
        self.console_logger.addHandler(logging.StreamHandler(stream=sys.stdout))

        client_update_logger = mp.get_logger()
        client_update_logger.setLevel(logging.INFO)
        client_update_logger.addFilter(self.update_status)

        self.tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.tls_context.load_cert_chain(certfile="server/certificate/cert.pem",
                                         keyfile="server/certificate/cert-key.pem")
        self.tls_context.minimum_version = ssl.TLSVersion.TLSv1_3

        if record_tls_secrets:
            self.tls_context.keylog_filename = f"server/logs/secrets/secrets_log.log"

        self.is_alive = True

        self.handle_client()

    def wrap_tls(self):
        self.socket = self.tls_context.wrap_socket(self.socket, server_side=True)
        cipher, tls_version, secret_bit_num = self.socket.cipher() if self.socket.cipher() is not None else None, None, None
        self.console_logger.info(f"Completed TLS handshake with client {self.name}; using {tls_version}, "
                                 f"with cipher {cipher}")

    def update_status(self, record: logging.LogRecord):
        if self.is_alive:
            send_packet(self.socket, build_packet("201", {"status": record.getMessage()}))
        return self.is_alive

    def handle_client(self) -> None:
        self.socket.settimeout(3)
        try:
            self.wrap_tls()
            request_packet = recv_packet(self.socket, True)
            match request_packet.code:
                # Do stuff here
                case _:
                    pass

        except ConnectionError:
            # if raised, the connection is dead
            self.console_logger.warning(f"Client {self.name} closed the connection unexpectedly")
            self.disconnect(None)
        except TimeoutError:
            self.console_logger.warning(f"Client {self.name} took too long to respond.")
            self.disconnect(None)
        except ssl.SSLError as e:
            # if raised, the connection is dead
            self.console_logger.warning(f"A TLS connection error occurred: {e}")
            self.disconnect(None)
        except TransmissionProtocolError as e:
            self.console_logger.warning(f"A transmission protocol error occurred: {e}")
            self.disconnect(build_packet("501"))
        except PacketStructureError as e:
            self.console_logger.warning(f"A Packet structure error occurred: {e}")
            self.disconnect(build_packet("502"))
        except PacketContentsError as e:
            self.console_logger.warning(f"A Packet contents error occurred: {e}")
            self.disconnect(build_packet("503", {"description": e.__str__()}))
        else:
            self.console_logger.info(f"Communication completed successfully with client {self.name}, "
                                     f"closing the connection, and terminating client handler thread")
            self.disconnect(build_packet("500", {"reason": "End of communication."}))
        finally:
            self.console_logger.info(f"Finished handling client {self.name}")
            self.is_alive = False


    def disconnect(self, disconnect_packet: bytes | None):
        logger = logging.getLogger("server_console")
        logger.info(f"Disconnecting client {self.name}")
        if disconnect_packet is not None:
            try:
                send_packet(self.socket, disconnect_packet)
            except (ConnectionError, ssl.SSLError):
                pass
        self.socket.close()
