# transmission specifications
PORT = 8374  # shared port
CHARSET = 'utf-8'
LFS = 24  # length field size
RECV_BUFFER_SIZE = 128000

# packet structure
SEP = b"\x1d\x0d"  # protocol seperator: group seperator + carriage return
END = b"\x04"  # end of packet marker
MAX_TITLE_SIZE = 128  # 128B aka 128 characters
MAX_FIELD_SIZE = 128  # 128B aka 128 characters
MAX_FILE_SIZE = int(1.6e7)  # 16MB

# packet codes
"""
"CODE": ("DESCRIPTION",
        [
            "header1name",
            "header2name",
        ]),
    "000": ("", 
            []),
"""
CODES: dict[str, tuple[str, list[str]]] = {
    # 0xx: Informational, file uploads
    "000": ("File upload",
            []),

    # 1xx: Client requests and related (only client sends)


    # 2xx: Server replies, updates and related (only server sends)


    # 3xx: Client-specific connection termination messages (client sends to server)

    # 4xx: Server-specific connection termination messages (server sends to client)
    "400": ("Internal server error",
            []),


    # 5xx: Protocol and non-side specific errors (allways followed by disconnecting)
    "500": ("Disconnect notification",
            [
                "reason",
            ]),
    "501": ("Transmission protocol error",
            []),
    "502": ("Packet structure error",
            []),
    "503": ("Packet contents error",
            [
                "description",
            ]),
}
