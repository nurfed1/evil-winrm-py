import base64
import datetime
import logging
import os
import random
import re
import string
import struct
import typing

from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import HMAC, MD5
from impacket import LOG
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REP, AP_REQ, EncAPRepPart, KRB_ERROR, TGS_REP, Authenticator, seq_set
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.gssapi import (
    GSS_C_CONF_FLAG,
    GSS_C_INTEG_FLAG,
    GSS_C_MUTUAL_FLAG,
    GSS_C_REPLAY_FLAG,
    GSS_C_SEQUENCE_FLAG,
    GSS_HMAC,
    GSS_RC4,
    GSSAPI as create_kerberos_cipher,
    GSSAPI_RC4,
    KG_USAGE_ACCEPTOR_SEAL,
    KG_USAGE_INITIATOR_SEAL,
    CheckSumField,
)
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGS, getKerberosTGT
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type.univ import noValue
from requests.auth import AuthBase

from pypsrp._utils import get_hostname
from pypsrp.exceptions import AuthenticationError

log = logging.getLogger(__name__)

_RC4_GSS_WRAP_HEADER = b"\x60\x2b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"

try:
    _rand = random.SystemRandom()
except NotImplementedError:
    _rand = random


class MechIndepToken:
    def __init__(self, data: bytes, oid: bytes = b"\x06\t*\x86H\x86\xf7\x12\x01\x02\x02"):
        self.data = data
        self.token_oid = oid

    @staticmethod
    def from_bytes(data: bytes) -> "MechIndepToken":
        if data[:1] != b"\x60":
            raise ValueError("Incorrect token data")

        data = data[1:]
        length, data = MechIndepToken._get_length(data)
        token_data = data[:length]
        oid_length, token_data = MechIndepToken._get_length(token_data[1:])
        token_oid = token_data[: oid_length + 2]
        token_data = token_data[oid_length + 2 :]
        return MechIndepToken(token_data, token_oid)

    @staticmethod
    def _get_length(data: bytes) -> tuple[int, bytes]:
        if data[0] < 128:
            return data[0], data[1:]

        bytes_count = data[0] - 128
        return int.from_bytes(data[1 : 1 + bytes_count], byteorder="big", signed=False), data[1 + bytes_count :]

    @staticmethod
    def _encode_length(length: int) -> bytes:
        if length < 128:
            return length.to_bytes(1, byteorder="big", signed=False)

        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return (128 + len(length_bytes)).to_bytes(1, byteorder="big", signed=False) + length_bytes

    def to_bytes(self) -> tuple[bytes, bytes]:
        token = self.token_oid + self.data
        token = b"\x60" + self._encode_length(len(token)) + token
        header_end = len(token) - len(self.data)
        return token[:header_end], self.data


class KerberosCipher:
    def __init__(self, cipher: type, session_key: Key):
        self.cipher = create_kerberos_cipher(cipher)
        self.session_key = session_key

    def encrypt(self, data: bytes, sequence_number: int) -> tuple[bytes, bytes, int]:
        if isinstance(self.cipher, GSSAPI_RC4):
            return self._encrypt_rc4(data, sequence_number)
        return self._encrypt_aes(data, sequence_number)

    def decrypt(self, header: bytes, data: bytes) -> bytes:
        if isinstance(self.cipher, GSSAPI_RC4):
            return self._decrypt_rc4(header, data)
        return self._decrypt_aes(header, data)

    def _encrypt_aes(self, data: bytes, sequence_number: int) -> tuple[bytes, bytes, int]:
        if isinstance(self.cipher, GSSAPI_RC4):
            raise ValueError("RC4 cipher cannot be used for AES encryption")

        # WinRM expects the RFC 4121 CFX wrap split used by GSS IOV. The generic
        # Impacket GSS_Wrap path adds block padding for non-aligned payloads,
        # which changes the clear header length (e.g. 0x4b instead of 0x3c) and
        # causes WinRM to reject the request. The LDAP helper uses the same AES
        # CFX token shape without the extra padding, which matches native WinRM.
        rotated_ciphertext, token_bytes = self.cipher.GSS_Wrap_LDAP(
            self.session_key, data, sequence_number, use_padding=False
        )
        token = self.cipher.WRAP(token_bytes)
        header_length = len(self.cipher.WRAP()) + token["RRC"] + token["EC"]
        header = token_bytes + rotated_ciphertext[:header_length]
        encrypted_data = rotated_ciphertext[header_length:]
        return encrypted_data, header, token["EC"]

    def _decrypt_aes(self, header: bytes, data: bytes) -> bytes:
        if isinstance(self.cipher, GSSAPI_RC4):
            raise ValueError("RC4 cipher cannot be used for AES decryption")

        token = self.cipher.WRAP(header[:16])
        cipher = self.cipher.cipherType()
        rotated_data = header[16:] + data
        cipher_text = self.cipher.unrotate(rotated_data, token["RRC"] + token["EC"])
        plain_text = cipher.decrypt(self.session_key, KG_USAGE_ACCEPTOR_SEAL, cipher_text)
        return plain_text[: -(token["EC"] + 16)]

    def _encrypt_rc4(self, data: bytes, sequence_number: int) -> tuple[bytes, bytes, int]:
        if not isinstance(self.cipher, GSSAPI_RC4):
            raise ValueError("AES cipher cannot be used for RC4 encryption")

        encrypted_data, header = self.cipher.GSS_Wrap(self.session_key, data, sequence_number)
        padding_length = len(encrypted_data) - len(data)
        return encrypted_data, header, padding_length

    def _decrypt_rc4(self, header: bytes, data: bytes) -> bytes:
        if not isinstance(self.cipher, GSSAPI_RC4):
            raise ValueError("AES cipher cannot be used for RC4 decryption")

        wrap, data = self._parse_rc4_wrap(header, data)

        k_seq = HMAC.new(self.session_key.contents, struct.pack("<L", 0), MD5).digest()
        k_seq = HMAC.new(k_seq, wrap["SGN_CKSUM"], MD5).digest()
        snd_seq = ARC4.new(k_seq).decrypt(wrap["SND_SEQ"])

        k_local = bytearray()
        for byte in bytes(self.session_key.contents):
            k_local.append(byte ^ 0xF0)

        k_crypt = HMAC.new(k_local, struct.pack("<L", 0), MD5).digest()
        k_crypt = HMAC.new(k_crypt, snd_seq[:4], MD5).digest()

        rc4 = ARC4.new(k_crypt)
        plaintext_with_confounder = rc4.decrypt(wrap["Confounder"] + data)
        plaintext = plaintext_with_confounder[8:]
        if not plaintext:
            return plaintext

        padding_length = plaintext[-1]
        if 1 <= padding_length <= 8 and plaintext.endswith(bytes([padding_length]) * padding_length):
            return plaintext[:-padding_length]

        return plaintext

    def _parse_rc4_wrap(self, header: bytes, data: bytes) -> tuple[typing.Any, bytes]:
        wrap_size = len(self.cipher.WRAP())
        token_bytes = header

        if header.startswith(b"\x60"):
            try:
                token_bytes = self._extract_gss_payload_prefix(header)
                log.debug(
                    "Parsed GSS-wrapped RC4 WinRM header (header=%d, token_prefix=%d)",
                    len(header),
                    len(token_bytes),
                )
            except Exception:
                log.debug("Failed to parse GSS-wrapped RC4 WinRM header", exc_info=True)
                token_bytes = header

        elif header.startswith(_RC4_GSS_WRAP_HEADER):
            token_bytes = header[len(_RC4_GSS_WRAP_HEADER) :]

        if len(token_bytes) >= wrap_size:
            log.debug("Using full RC4 WinRM header token (header=%d)", len(header))
            return self.cipher.WRAP(token_bytes[:wrap_size]), data

        if len(token_bytes) + len(data) >= wrap_size:
            missing = wrap_size - len(token_bytes)
            wrap_bytes = token_bytes + data[:missing]
            log.debug(
                "Using RC4 WinRM header token split across header/data (header=%d, continued=%d)",
                len(header),
                missing,
            )
            return self.cipher.WRAP(wrap_bytes), data[missing:]

        raise ValueError("Invalid RC4 WinRM header")

    def _extract_gss_payload_prefix(self, header: bytes) -> bytes:
        if not header.startswith(b"\x60"):
            return header

        offset = 1
        if len(header) <= offset:
            raise ValueError("Truncated GSS token")

        first_length = header[offset]
        offset += 1
        if first_length >= 128:
            length_octets = first_length - 128
            if len(header) < offset + length_octets:
                raise ValueError("Truncated GSS length")
            offset += length_octets

        if len(header) <= offset or header[offset] != 0x06:
            raise ValueError("Missing GSS OID tag")
        offset += 1

        if len(header) <= offset:
            raise ValueError("Truncated GSS OID length")

        oid_length = header[offset]
        offset += 1
        if oid_length >= 128:
            oid_length_octets = oid_length - 128
            if len(header) < offset + oid_length_octets:
                raise ValueError("Truncated GSS OID")
            oid_length = int.from_bytes(header[offset : offset + oid_length_octets], byteorder="big", signed=False)
            offset += oid_length_octets

        if len(header) < offset + oid_length:
            raise ValueError("Truncated GSS OID value")

        offset += oid_length
        return header[offset:]


def _unwrap_kerberos_response_token(response_token: bytes) -> bytes:
    if not response_token.startswith(b"\x60"):
        return response_token

    try:
        mech_token = MechIndepToken.from_bytes(response_token)
    except Exception:
        log.debug("Failed to parse GSS-wrapped Kerberos response token", exc_info=True)
        return response_token

    return mech_token.data


def _get_kerberos_type3(cipher: type, session_key: Key, auth_data: bytes) -> tuple[type, Key, bytes, int]:
    neg_token_resp = SPNEGO_NegTokenResp(auth_data)
    response_token = neg_token_resp["ResponseToken"]
    kerberos_token = _unwrap_kerberos_response_token(response_token)

    try:
        krb_error = KerberosError(packet=decoder.decode(kerberos_token, asn1Spec=KRB_ERROR())[0])
    except Exception:
        pass
    else:
        raise krb_error

    ap_rep = decoder.decode(kerberos_token, asn1Spec=AP_REP())[0]

    cipher_text = ap_rep["enc-part"]["cipher"]

    # Key Usage 12:
    # AP-REP encrypted part, encrypted with the application session key.
    plain_text = cipher.decrypt(session_key, 12, cipher_text)
    enc_ap_rep_part = decoder.decode(plain_text, asn1Spec=EncAPRepPart())[0]

    response_cipher = _enctype_table[int(enc_ap_rep_part["subkey"]["keytype"])]()
    response_session_key = Key(response_cipher.enctype, enc_ap_rep_part["subkey"]["keyvalue"].asOctets())
    sequence_number = int(enc_ap_rep_part["seq-number"])

    enc_ap_rep_part["subkey"].clear()
    enc_ap_rep_part = enc_ap_rep_part.clone()

    now = datetime.datetime.now(datetime.timezone.utc)
    enc_ap_rep_part["cusec"] = now.microsecond
    enc_ap_rep_part["ctime"] = KerberosTime.to_asn1(now)
    enc_ap_rep_part["seq-number"] = sequence_number
    encoded_authenticator = encoder.encode(enc_ap_rep_part)

    encrypted_authenticator = response_cipher.encrypt(session_key, 12, encoded_authenticator, None)

    ap_rep["enc-part"].clear()
    ap_rep["enc-part"]["etype"] = response_cipher.enctype
    ap_rep["enc-part"]["cipher"] = encrypted_authenticator

    response = SPNEGO_NegTokenResp()
    response["ResponseToken"] = encoder.encode(ap_rep)

    return response_cipher, response_session_key, response.getData(), sequence_number


class ImpacketKerberosContext:
    def __init__(self, cipher: type, session_key: Key, initiator_sequence_number: int):
        self._cipher = cipher
        self._session_key = session_key
        self._crypto = KerberosCipher(cipher, session_key)
        self._sequence_number = initiator_sequence_number
        self._peer_sequence_number: int | None = None
        self.complete = False
        self.response_auth_header = "kerberos"

    def wrap_winrm(self, data: bytes) -> tuple[bytes, bytes, int]:
        sealed_message, signature, padding_length = self._crypto.encrypt(data, self._sequence_number)
        self._sequence_number += 1
        return signature, sealed_message, padding_length

    def unwrap_winrm(self, header: bytes, data: bytes) -> bytes:
        return self._crypto.decrypt(header, data)

    def step(self, auth_data: bytes | None) -> bytes | None:
        if self.complete or auth_data in [None, b""]:
            self.complete = True
            return None

        try:
            neg_token_resp = SPNEGO_NegTokenResp(auth_data)
        except Exception:
            neg_token_resp = None
        else:
            response_token = neg_token_resp.fields.get("ResponseToken")
            neg_state = neg_token_resp.fields.get("NegState")

            if response_token in [None, b""]:
                if neg_state == b"\x00":
                    log.debug("Received final SPNEGO accept-completed token without response payload")
                    self.complete = True
                    return None

                if neg_state == b"\x02":
                    raise AuthenticationError("Server rejected the Kerberos negotiation")

        cipher, session_key, response, sequence_number = _get_kerberos_type3(
            self._cipher, self._session_key, auth_data
        )
        self._cipher = cipher
        self._session_key = session_key
        self._crypto = KerberosCipher(cipher, session_key)
        self._peer_sequence_number = sequence_number
        log.debug(
            "Completed Kerberos context negotiation; peer sequence=%d, next initiator sequence=%d, enctype=%s",
            sequence_number,
            self._sequence_number,
            getattr(cipher, "enctype", "unknown"),
        )
        self.complete = True
        return response


def _split_username(username: str | None) -> tuple[str, str]:
    if not username:
        return "", ""

    if "\\" in username:
        domain, user = username.split("\\", 1)
        return domain, user

    if "@" in username:
        user, domain = username.rsplit("@", 1)
        return domain, user

    return "", username


def _load_ccache() -> CCache | None:
    krb5ccname = os.getenv("KRB5CCNAME")
    if not krb5ccname:
        return None

    try:
        ccache = CCache.loadFile(krb5ccname)
        log.debug("Loaded Kerberos cache from %s", krb5ccname)
        return ccache
    except Exception as exc:
        log.debug("Failed to load Kerberos cache %s: %s", krb5ccname, exc)
        return None


def get_cached_kerberos_principal(service: str, hostname: str, username: str | None = None) -> str:
    del service, hostname
    ccache = _load_ccache()
    if ccache is None or ccache.principal is None or ccache.principal.realm is None:
        raise ValueError("No Kerberos credentials cache found")

    cache_user = "/".join(component["data"].decode("utf-8") for component in ccache.principal.components)
    cache_domain = ccache.principal.realm["data"].decode("utf-8")

    requested_domain, requested_user = _split_username(username)
    if requested_user and requested_user.lower() != cache_user.lower():
        raise ValueError("Requested username does not match the Kerberos cache principal")
    if requested_domain and requested_domain.lower() != cache_domain.lower():
        raise ValueError("Requested realm does not match the Kerberos cache principal")

    return "%s@%s" % (cache_user, cache_domain)


def _get_tgs(username: str | None, password: str | None, target_name: str, service: str) -> tuple[bytes, type, Key, str, str]:
    domain, user = _split_username(username)
    password = password or ""
    lmhash = b""
    nthash = b""
    aes_key = b""

    ccache = _load_ccache()
    tgt = None
    tgs = None

    if ccache is not None and ccache.principal is not None and ccache.principal.realm is not None:
        cache_domain = ccache.principal.realm["data"].decode("utf-8")
        cache_user = "/".join(component["data"].decode("utf-8") for component in ccache.principal.components)

        if user and user.lower() != cache_user.lower():
            log.debug("Ignoring Kerberos cache because user %s does not match cache principal %s", user, cache_user)
            ccache = None
        elif domain and domain.lower() != cache_domain.lower():
            log.debug("Ignoring Kerberos cache because realm %s does not match cache realm %s", domain, cache_domain)
            ccache = None

    if ccache is not None and ccache.principal is not None and ccache.principal.realm is not None:
        cache_domain = ccache.principal.realm["data"].decode("utf-8")
        cache_user = "/".join(component["data"].decode("utf-8") for component in ccache.principal.components)

        if not domain:
            domain = cache_domain

        principal = "%s/%s@%s" % (service, target_name.upper(), domain.upper())
        creds = ccache.getCredential(principal)
        if creds is not None:
            tgs = creds.toTGS(principal)
            user = creds["client"].prettyPrint().split(b"@")[0].decode("utf-8")
            log.debug("Using %s service ticket from cache", service)
        else:
            principal = "krbtgt/%s@%s" % (domain.upper(), domain.upper())
            creds = ccache.getCredential(principal)
            if creds is not None:
                tgt = creds.toTGT()
                user = user or cache_user
                log.debug("Using TGT from cache")
            else:
                user = user or cache_user

    if not user:
        raise ValueError("No Kerberos username was provided and no matching credentials cache was found")
    if not domain:
        raise ValueError("No Kerberos realm could be determined. Use user@REALM or provide a matching cache")

    user_principal = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    while True:
        if tgt is None:
            if tgs is None:
                if not password and not lmhash and not nthash and not aes_key:
                    raise ValueError("No Kerberos credentials were found in the cache and no password was provided")

                try:
                    tgt_data, cipher, _, session_key = getKerberosTGT(
                        user_principal, password, domain, lmhash, nthash, aes_key, None
                    )
                except KerberosError as exc:
                    if exc.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                        if not lmhash and not nthash and not aes_key:
                            from impacket.ntlm import compute_lmhash, compute_nthash

                            LOG.debug("Got KDC_ERR_ETYPE_NOSUPP, falling back to RC4")
                            lmhash = compute_lmhash(password)
                            nthash = compute_nthash(password)
                            continue
                    raise
            else:
                tgt_data = b""
                cipher = tgs["cipher"]
                session_key = tgs["sessionKey"]
        else:
            tgt_data = tgt["KDC_REP"]
            cipher = tgt["cipher"]
            session_key = tgt["sessionKey"]

        if tgs is None:
            server_name = Principal("%s/%s" % (service, target_name), type=constants.PrincipalNameType.NT_SRV_INST.value)
            try:
                tgs_data, cipher, _, session_key = getKerberosTGS(server_name, domain, None, tgt_data, cipher, session_key)
            except KerberosError as exc:
                if exc.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                    if not lmhash and not nthash and not aes_key:
                        from impacket.ntlm import compute_lmhash, compute_nthash

                        LOG.debug("Got KDC_ERR_ETYPE_NOSUPP, falling back to RC4")
                        lmhash = compute_lmhash(password)
                        nthash = compute_nthash(password)
                        continue
                raise
            return tgs_data, cipher, session_key, user, domain

        return tgs["KDC_REP"], tgs["cipher"], tgs["sessionKey"], user, domain


def build_kerberos_context(
    username: str | None, password: str | None, hostname: str, service: str
) -> tuple[ImpacketKerberosContext, bytes]:
    tgs, cipher, session_key, cache_user, domain = _get_tgs(username, password, hostname, service)
    principal = Principal(cache_user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    initiator_sequence_number = _rand.getrandbits(32)

    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]

    tgs_rep = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs_rep["ticket"])

    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req["ap-options"] = constants.encodeFlags([constants.APOptions.mutual_required.value])
    seq_set(ap_req, "ticket", ticket.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = domain
    seq_set(authenticator, "cname", principal.components_to_asn1)

    now = datetime.datetime.now(datetime.timezone.utc)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    authenticator["cksum"] = noValue
    authenticator["cksum"]["cksumtype"] = 0x8003
    checksum = CheckSumField()
    checksum["Lgth"] = 16
    checksum["Flags"] = (
        GSS_C_CONF_FLAG
        | GSS_C_INTEG_FLAG
        | GSS_C_SEQUENCE_FLAG
        | GSS_C_REPLAY_FLAG
        | GSS_C_MUTUAL_FLAG
    )
    authenticator["cksum"]["checksum"] = checksum.getData()
    authenticator["seq-number"] = initiator_sequence_number

    encoded_authenticator = encoder.encode(authenticator)
    encrypted_authenticator = cipher.encrypt(session_key, 11, encoded_authenticator, None)

    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = encrypted_authenticator
    blob["MechToken"] = encoder.encode(ap_req)

    log.debug(
        "Built initial Kerberos AP-REQ for %s/%s with initiator sequence=%d and enctype=%s",
        service,
        hostname,
        initiator_sequence_number,
        getattr(cipher, "enctype", "unknown"),
    )
    return ImpacketKerberosContext(cipher, session_key, initiator_sequence_number), blob.getData()


class HTTPImpacketKerberosAuth(AuthBase):
    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        service: str = "http",
        hostname_override: str | None = None,
        wrap_required: bool = False,
        send_cbt: bool = True,
        delegate: bool = False,
    ) -> None:
        self.username = username
        self.password = password
        self.service = service
        self.hostname_override = hostname_override
        self.wrap_required = wrap_required
        self.send_cbt = send_cbt
        self.delegate = delegate
        self.contexts: dict[str, ImpacketKerberosContext] = {}
        self._regex = re.compile(r"(Kerberos|Negotiate)\s*([^,]*),?", re.I)

    def __call__(self, request):
        request.headers["Connection"] = "Keep-Alive"
        request.register_hook("response", self.response_hook)
        return request

    def response_hook(self, response, **kwargs):
        if response.status_code == 401:
            response = self.handle_401(response, **kwargs)

        return response

    def handle_401(self, response, **kwargs):
        response_auth_header = self._check_auth_supported(response, ["Negotiate", "Kerberos"])
        response_auth_header_l = response_auth_header.lower()

        host = get_hostname(response.url)
        auth_hostname = self.hostname_override or host

        try:
            context, out_token = build_kerberos_context(self.username, self.password, auth_hostname, self.service)
        except ValueError as exc:
            raise AuthenticationError(str(exc))

        context.response_auth_header = response_auth_header_l
        self.contexts[host] = context

        while True:
            response.content
            response.raw.release_conn()

            request = response.request.copy()
            log.debug("Sending http request with Impacket Kerberos token")
            self._set_auth_token(request, out_token, response_auth_header)
            response = response.connection.send(request, **kwargs)

            in_token = self._get_auth_token(response)
            if in_token in [None, b""]:
                log.debug("Did not receive a HTTP auth response token, stopping authentication process")
                break

            out_token = context.step(in_token)
            if response.status_code != 401:
                log.debug(
                    "Received final HTTP status %s during Kerberos auth, stopping token exchange",
                    response.status_code,
                )
                break

            if out_token is None:
                log.debug("Kerberos auth context did not return a continuation token on a 401 response")
                break

        return response

    @staticmethod
    def _check_auth_supported(response, auth_providers):
        auth_supported = response.headers.get("www-authenticate", "")
        matched_providers = [provider for provider in auth_providers if provider.upper() in auth_supported.upper()]
        if not matched_providers:
            raise AuthenticationError(
                "The server did not response with one of the following authentication methods "
                "%s - actual: '%s'" % (", ".join(auth_providers), auth_supported)
            )

        return matched_providers[0]

    @staticmethod
    def _set_auth_token(request, token, auth_provider):
        encoded_token = base64.b64encode(token).decode("ascii")
        request.headers["Authorization"] = "%s %s" % (auth_provider, encoded_token)

    def _get_auth_token(self, response) -> bytes | None:
        auth_header = response.headers.get("www-authenticate", "")
        token_match = self._regex.search(auth_header)
        if not token_match:
            return None

        token = token_match.group(2)
        if not token:
            return b""

        return base64.b64decode(token)
