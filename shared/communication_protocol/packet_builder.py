import shared.communication_protocol.packet_structure as structure


def build_header(name: str, value: str | int | float) -> str:
    """
    Builds a header line
    :param name: the name of the header we want to create
    :param value: the value of the header we want to create
    :return: the header line in str format
    """
    return name + ":" + str(value) + structure.SEP


def build_packet(code: str, headers: dict[str, str] | None) -> str:
    """
    Builds a packet in the shared' structure
    :param code: the packets' code
    :param headers: the packets' headers (if any)
    :return: the packet in str format
    """
    code_line = code + ":" + structure.CODES[code][0] + structure.SEP
    if headers is None:
        return code_line + structure.END
    header_lines = ""
    for header, value in headers.items():
        header_lines += build_header(header, value)
    return code_line + header_lines + structure.END
