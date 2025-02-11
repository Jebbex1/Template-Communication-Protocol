import socket as socket
import shared.communication_protocol.packet_builder as builder


PORT = 8374  # shared port
CHARSET = 'utf-8'
LFS = 5  # length field size


def recv_packet(skt: socket.socket) -> str:
    """
    Receives a packet by the transmission protocol, and returns it as a string.
    :param skt: the socket interface that we can use to communicate
    :raises ValueError: if the packet received does not follow the transmission protocol
    :return: the received packet
    """
    length = skt.recv(LFS).decode()  # receive packet length
    if not length.isnumeric():
        send_packet(skt, builder.build_packet("500", None))
        raise ValueError(f"Socket at address {skt.getsockname()[0]}:{str(skt.getsockname()[1])} sent a packet doesn't "
                         f"follow the transmission protocol")
    length = int(length)
    packet = skt.recv(length)
    return packet.decode(CHARSET)


def gen_len_prefix(length: int) -> str:
    """
    Generates a prefix string for the length of the packet.
    :param length: length of the packet
    :return: a prefix string of constant length that represents the length of the packet
    """
    return str(length).zfill(LFS)


def send_packet(skt: socket.socket, packet: str) -> None:
    """
    Sends a packet according transmission protocol.
    :param skt: the socket interface that we use to communicate
    :param packet: the packet to send
    """
    prefix = gen_len_prefix(len(packet))
    encoded = (prefix + packet).encode(CHARSET)
    skt.send(encoded)
