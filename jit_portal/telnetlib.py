"""Telnetlib shim for Python 3.13 compatibility"""
# This is a minimal shim to make netmiko work with Python 3.13
# Netmiko imports telnetlib but doesn't actually use it for SSH connections

# Telnet protocol characters
IAC = bytes([255])  # "Interpret As Command"
DONT = bytes([254])
DO = bytes([253])
WONT = bytes([252])
WILL = bytes([251])
SB = bytes([250])  # Subnegotiation Begin
SE = bytes([240])  # Subnegotiation End

# Telnet protocol options
TTYPE = bytes([24])  # Terminal Type

class Telnet:
    """Minimal Telnet class stub"""
    pass
