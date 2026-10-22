"""Small conversions shared by the extractors. All of them are forgiving:
anything that doesn't parse returns None and the caller records a warning."""
import ipaddress


def to_interface_ip(address, mask=None):
    """
    ('10.0.0.1', '255.255.255.0') -> '10.0.0.1/24'. Also accepts '10.0.0.1/24'
    and a prefix length as mask. Returns None for 0.0.0.0/0.0.0.0 (FortiOS'
    "no address") and for anything that isn't an address.
    """
    if not address:
        return None
    try:
        if mask is None:
            iface = ipaddress.ip_interface(address)
        else:
            iface = ipaddress.ip_interface(f'{address}/{mask}')
    except ValueError:
        return None
    if int(iface.ip) == 0 and iface.network.prefixlen == 0:
        return None
    if int(iface.ip) == 0:
        return None
    return iface.with_prefixlen


def to_network(address, mask=None):
    """('10.0.0.0', '255.255.255.0') -> '10.0.0.0/24' (host bits cleared)."""
    if not address:
        return None
    try:
        text = address if mask is None else f'{address}/{mask}'
        return ipaddress.ip_network(text, strict=False).with_prefixlen
    except ValueError:
        return None


def network_of(interface_ip):
    """'10.0.0.1/24' -> '10.0.0.0/24'."""
    try:
        return ipaddress.ip_interface(interface_ip).network.with_prefixlen
    except ValueError:
        return None


def to_ip(address):
    """A single address, or None ('0.0.0.0' counts as none)."""
    if not address:
        return None
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if int(ip) == 0:
        return None
    return str(ip)


def pairs_to_prefix(tokens):
    """['10.0.0.0', '255.255.255.0'] or ['10.0.0.0/24'] -> '10.0.0.0/24'."""
    if not tokens:
        return None
    if len(tokens) >= 2:
        return to_network(tokens[0], tokens[1])
    return to_network(tokens[0])


def parse_port_range(token):
    """
    FortiOS service ports: 'dst[-dst_hi][:src[-src_hi]]', e.g. '80', '1-65535',
    '53:1024-65535'. Returns {'low', 'high', 'src_low', 'src_high'} or None.
    """
    if not token:
        return None
    dst, _, src = token.partition(':')

    def _range(text):
        if not text:
            return None, None
        low, _, high = text.partition('-')
        try:
            low = int(low)
            high = int(high) if high else low
        except ValueError:
            return None, None
        if not (0 <= low <= 65535 and 0 <= high <= 65535) or high < low:
            return None, None
        return low, high

    low, high = _range(dst)
    if low is None:
        return None
    src_low, src_high = _range(src)
    return {'low': low, 'high': high, 'src_low': src_low, 'src_high': src_high}


def int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
