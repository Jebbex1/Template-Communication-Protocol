import re

import shared.communication_protocol.packet_structure as structure
import shared.communication_protocol.transmission as transmission

# a regex that matches any correctly structured packets (does not check packet parameters, only its structure)
PACKET_PATTERN = (
    r"^("  # starts with 
    r"\d{3}:[\w\x20]+\x1D\x0D"  # code and description
    r"([\w-]+:[\x20-\x7E]+\x1D\x0D)*"  # headers (zero or more)
    r")"
    
    r".*"  # body
    r"(\x04)$"  # ends with EOT
    # \x20-\x7E represents eve ascii character between space and ~
).encode()


def is_valid_packet_syntax(content: bytes) -> bool:
    """
    Checks if a packets structure is correct.
    :param content: the string to check
    :return: True if the string matches the structures' RegEx pattern, False otherwise
    """
    try:
        return re.search(PACKET_PATTERN, content).string is not None
    except AttributeError:
        return False


def get_packet_code(packet: bytes) -> (str, str):
    """
    Gets the packet code and description from the raw packet string
    :param packet: the raw packet string
    :return: <packet code>,<packet string>
    """
    return packet.split(structure.SEP)[0].split(b":")


def get_headers_dict(packet: bytes) -> dict:
    """
    Gets the headers of the packet, and parses them into a dictionary
    :param packet: the raw packet string
    :return: a dictionary of the packet headers,  dict key -> header name and dict value -> header value
    """
    header_structure_match = re.findall(r"([\w-]+:[\x20-\x7E]+\x1D\x0D)".encode(), packet)
    headers_dict = {}
    for match in header_structure_match:
        print(match)
        segments = match.split(b":")
        header, value = segments[0], b":".join(segments[1:])
        headers_dict[header] = value
    return headers_dict


class PacketInfo:
    def __init__(self, packet: bytes):
        # Temporary assignment, only until parsing. Because the functions that parse the packet are unsafe until we
        # verify the packets' structure. After checking the packets' structure we can use the parsing method to assign
        # values to the attributes
        self.code, self.desc, self.headers, self.body = None, None, None, None

        self.raw_packet = packet
        self.follows_pattern = is_valid_packet_syntax(packet)

    def parse(self) -> None:
        """
        Parses the raw packet into attributes.
        """
        self.code, self.desc = get_packet_code(self.raw_packet)
        self.headers = get_headers_dict(self.raw_packet)

    def __str__(self) -> str:
        """
        Regular __str__ function
        """
        headers = "\n    ".join(f"{k}:{v}" for k, v in self.headers.items())
        return (
            "PacketInfo:\n"
            f"    {self.code}:{self.desc}\n"
            f"    {headers}\n"
        ).strip()


def is_consistent_packet(packet: PacketInfo) -> bool:
    """
    Verifies that the packets' code, description, and headers all match each other and that all headers are present
    :param packet: the raw packet string
    :return: does the packet's code match its description and headers
    """
    code, desc = packet.code, packet.desc
    headers = packet.headers
    try:
        if structure.CODES[code][0] != desc:
            return False
        for header_name in structure.CODES[code][1]:
            if header_name not in headers.keys():
                return False
        return True
    except KeyError:
        return False
