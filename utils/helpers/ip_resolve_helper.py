import socket
import ipaddress
from urllib.parse import urlparse
from typing import List

def resolve_to_public_ip(target: str, include_ipv6: bool = False) -> List[str]:
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname
        if not target:
            return []

    public_ips = set()

    try:
        ip_obj = ipaddress.ip_address(target)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local:
            return []
        if not include_ipv6 and ip_obj.version == 6:
            return []
        return [str(ip_obj)]
    except ValueError:
        pass

    # IPv4 resolution
    try:
        # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
        _, _, ipv4_list = socket.gethostbyname_ex(target)
        for ip in ipv4_list:
            ip_obj = ipaddress.ip_address(ip)
            if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local):
                public_ips.add(ip)
    except socket.gaierror:
        pass
    except Exception:
        pass

    # IPv6 resolution 
    if include_ipv6:
        try:
            addrinfo = socket.getaddrinfo(target, None, socket.AF_INET6, socket.SOCK_STREAM)
            ipv6_ips = list(set([addr[4][0] for addr in addrinfo]))
            for ip in ipv6_ips:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local):
                    if ip not in public_ips: 
                        public_ips.add(ip)
        except socket.gaierror:
            pass
        except Exception:
            pass

    return list(public_ips)