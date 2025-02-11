import socket
from datetime import datetime

import shared.communication_protocol.transmission as transmission
import shared.communication_protocol.packet_builder as builder
import shared.communication_protocol.packet_analyzer as analyzer


def recv_and_parse(skt: socket.socket) -> analyzer.PacketInfo:
    """
    Receives a packet from the socket, if the packet follows the shared' RegEx pattern for packets, it parses the
    packet. After parsing, it verifies that the packets' content is consistent, then returns it.
    :param skt: the socket interface to receive the packet from
    :return: the parsed packet
    :raises ValueError: if the packet does not follow the shared' RegEx pattern, or if the packets' content is
    inconsistent
    """
    packet = transmission.recv_packet(skt)  # receive packet
    packet_info = analyzer.PacketInfo(packet)

    # check structure
    if not packet_info.follows_pattern:
        transmission.send_packet(skt, builder.build_packet("501", None))
        raise ValueError(f"Socket {skt_addr(skt)} sent a packet that does not follow correct structure, "
                         f"packet: {repr(packet)}")
    packet_info.parse()

    # check consistency
    if not analyzer.is_consistent_packet(packet_info):
        transmission.send_packet(skt, builder.build_packet("502", None))
        raise ValueError(f"Socket {skt_addr(skt)} sent a non-consistent packet: {repr(packet)}")
    return packet_info


def skt_addr(skt: socket.socket) -> str:
    """
    Get socket address in the format ipv4:port
    :param skt: the socket interface we want to get the address of
    :return: sockets' address in the format ipv4:port
    """
    return skt.getsockname()[0] + ":" + str(skt.getsockname()[1])


def ftime():
    return datetime.now().strftime("%d-%m-%Y %H:%M:%S.%f")[:-3]
