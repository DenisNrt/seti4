import ipaddress
import time

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from ipwhois import IPWhois
from scapy.layers.inet import ICMP, IP, UDP, TCP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.sendrecv import sr1
from scapy.volatile import RandInt, RandShort
class Traceroute:
    @staticmethod
    def trace(ip_address, proto, timeout, max_hops, port, verbose):
        target = ipaddress.ip_address(ip_address)
        version = target.version
        if timeout <= 0:
            raise Exception("timeout should be greater than 0")
        if not 0 <= max_hops <= 255:
            raise Exception("max_hops should be between 0 and 255")

        addresses = []
        for i in range(1, max_hops + 1):
            start = time.time()
            ip_proto = IP(dst=ip_address, ttl=i) if version == 4 else IPv6(dst=ip_address, hlim=i)
            if proto == "icmp":
                req = ip_proto / ICMP(id=1234) if version == 4 else ip_proto / ICMPv6EchoRequest(id=1234)
            elif proto == "tcp":
                req = ip_proto / TCP(
                    sport=RandShort(),
                    dport=port,
                    flags="S",
                    seq=RandInt())
            else:
                req = ip_proto / UDP(dport=port)
            data = sr1(x=req, timeout=timeout, verbose=0)
            total = (time.time() - start) * 1000
            if not data:
                addresses.append(f"{i} *")
                continue
            res = f"{i} {data.src} {total:.2f}"
            if verbose:
                res += f" {Traceroute.get_as(data.src)}"
            addresses.append(res)
            # 11 это превышение времени жизни
            if ipaddress.ip_address(data.src) == target:
                break
        return "\n".join(addresses)

    @staticmethod
    def get_as(ip):
        if not ipaddress.ip_address(ip).is_global:
            return "-"

        try:
            result = IPWhois(ip).lookup_whois(asn_methods=["whois"])
            return result["asn"] or "-"

        except Exception:
            return "-"