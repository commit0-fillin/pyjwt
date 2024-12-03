import base64
import binascii
import re
from typing import Union
try:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
except ModuleNotFoundError:
    pass
_PEMS = {b'CERTIFICATE', b'TRUSTED CERTIFICATE', b'PRIVATE KEY', b'PUBLIC KEY', b'ENCRYPTED PRIVATE KEY', b'OPENSSH PRIVATE KEY', b'DSA PRIVATE KEY', b'RSA PRIVATE KEY', b'RSA PUBLIC KEY', b'EC PRIVATE KEY', b'DH PARAMETERS', b'NEW CERTIFICATE REQUEST', b'CERTIFICATE REQUEST', b'SSH2 PUBLIC KEY', b'SSH2 ENCRYPTED PRIVATE KEY', b'X509 CRL'}
_PEM_RE = re.compile(b'----[- ]BEGIN (' + b'|'.join(_PEMS) + b')[- ]----\r?\n.+?\r?\n----[- ]END \\1[- ]----\r?\n?', re.DOTALL)
_CERT_SUFFIX = b'-cert-v01@openssh.com'
_SSH_PUBKEY_RC = re.compile(b'\\A(\\S+)[ \\t]+(\\S+)')
_SSH_KEY_FORMATS = [b'ssh-ed25519', b'ssh-rsa', b'ssh-dss', b'ecdsa-sha2-nistp256', b'ecdsa-sha2-nistp384', b'ecdsa-sha2-nistp521']

def force_bytes(value: Union[str, bytes]) -> bytes:
    if isinstance(value, str):
        return value.encode('utf-8')
    elif isinstance(value, bytes):
        return value
    else:
        raise TypeError("Expected str or bytes, got %s" % type(value))

def base64url_decode(input: Union[str, bytes]) -> bytes:
    if isinstance(input, str):
        input = input.encode('ascii')
    rem = len(input) % 4
    if rem > 0:
        input += b'=' * (4 - rem)
    return base64.urlsafe_b64decode(input)

def base64url_encode(input: Union[str, bytes]) -> bytes:
    if isinstance(input, str):
        input = input.encode('utf-8')
    encoded = base64.urlsafe_b64encode(input)
    return encoded.rstrip(b'=')

def to_base64url_uint(val: int) -> bytes:
    if val < 0:
        raise ValueError("Must be a positive integer")
    int_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    return base64url_encode(int_bytes)

def from_base64url_uint(val: Union[str, bytes]) -> int:
    decoded = base64url_decode(val)
    return int.from_bytes(decoded, byteorder='big')

def constant_time_compare(val1: bytes, val2: bytes) -> bool:
    """
    Compare two strings in constant time to avoid timing attacks.

    Returns `True` if the two strings are equal, `False` otherwise.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= x ^ y
    return result == 0
