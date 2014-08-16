from __future__ import (absolute_import, print_function, division)
import ipaddress
from . import tcp


class SocksError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class VERSION(object):
    SOCKS4 = 0x04
    SOCKS5 = 0x05


class CMD(object):
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03


class ATYP(object):
    IPV4_ADDRESS = 0x01
    DOMAINNAME = 0x03
    IPV6_ADDRESS = 0x04


class REP(object):
    SUCCEEDED = 0x00
    GENERAL_SOCKS_SERVER_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class METHOD(object):
    NO_AUTHENTICATION_REQUIRED = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE_METHODS = 0xFF


class ClientGreeting(object):
    __slots__ = ("ver", "methods")

    def __init__(self, ver, methods):
        self.ver = ver
        self.methods = methods

    @classmethod
    def from_file(cls, f):
        ver, nmethods = f.read(2)
        methods = f.read(nmethods)
        return cls(ver, methods)

    def to_file(self, f):
        head = bytes((self.ver, len(self.methods)))
        f.write(head)
        f.write(self.methods)


class ServerGreeting(object):
    __slots__ = ("ver", "method")

    def __init__(self, ver, method):
        self.ver = ver
        self.method = method

    @classmethod
    def from_file(cls, f):
        ver, method = f.read(2)
        return cls(ver, method)

    def to_file(self, f):
        f.write(bytes((self.ver, self.method)))


class Message(object):
    __slots__ = ("ver", "msg", "atyp", "addr")

    def __init__(self, ver, msg, atyp, addr):
        self.ver = ver
        self.msg = msg
        self.atyp = atyp
        self.addr = addr

    @classmethod
    def from_file(cls, f):
        ver, msg, rsv, atyp = f.read(4)
        if rsv != 0x00:
            raise SocksError(REP.GENERAL_SOCKS_SERVER_FAILURE,
                             "Socks Request: Invalid reserved byte: %s" % rsv)

        if atyp == ATYP.IPV4_ADDRESS:
            host = ipaddress.IPv4Address(f.read(4)).compressed
            use_ipv6 = False
        elif atyp == ATYP.IPV6_ADDRESS:
            host = ipaddress.IPv6Address(f.read(16)).compressed
            use_ipv6 = True
        elif atyp == ATYP.DOMAINNAME:
            length = f.read(1)[0]
            host = f.read(length).decode("idna")
            use_ipv6 = False
        else:
            raise SocksError(REP.ADDRESS_TYPE_NOT_SUPPORTED,
                             "Socks Request: Unknown ATYP: %s" % atyp)

        port = int.from_bytes(f.read(2), byteorder="big")
        addr = tcp.Address((host, port), use_ipv6=use_ipv6)
        return cls(ver, msg, atyp, addr)

    def to_file(self, f):
        head = bytes((self.ver, self.msg, 0x00, self.atyp))
        f.write(head)
        if self.atyp == ATYP.IPV4_ADDRESS:
            f.write(ipaddress.IPv4Address(self.addr.host).packed)
        elif self.atyp == ATYP.IPV6_ADDRESS:
            f.write(ipaddress.IPv6Address(self.addr.host).packed)
        elif self.atyp == ATYP.DOMAINNAME:
            host = self.addr.host.encode("idna")
            f.write(bytes((len(host), )))
            f.write(host)
        else:
            raise SocksError(REP.ADDRESS_TYPE_NOT_SUPPORTED, "Unknown ATYP: %s" % self.atyp)
        f.write(self.addr.port.to_bytes(2, "big"))