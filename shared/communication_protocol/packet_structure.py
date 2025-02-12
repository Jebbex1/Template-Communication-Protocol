# WHEN CHANGING SEPERATOR AND END - ALSO CHANGE REGEX ACCORDINGLY
SEP = b"\x1d\x0d"  # protocol seperator: group seperator + carriage return
END = b"\x04"  # end of packet marker

"""
"CODE": ("DESCRIPTION",
        [
            "header1name",
            "header2name",
        ]),
"""
CODES = {
    # 0xx: Informational, handshake (both sides send)


    # 1xx: Client cracking info and updates (only client sends)


    # 2xx: Server replies AND updates (only server sends)


    # 3xx: Client-specific connection termination messages (client sends to server)


    # 4xx: Server-specific connection termination messages (server sends to client)
    "400": ("Internal server error",
            []),


    # 5xx: Protocol and non-side specific errors (allways followed by disconnecting)
    "500": ("Packet does not follow the transmission protocol",
            []),
    "501": ("Packet structure is invalid",
            []),
    "502": ("Packet contents are not consistent",
            []),
    "503": ("No implemented functionality for this packet code at this stage of communication",
            []),
    "504": ("No regular packets before handshake",
            []),
}
