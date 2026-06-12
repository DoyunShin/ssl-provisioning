"""Tests for the shared cryptographic helpers."""

import base64
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sslpv.utils import crypto


def _make_cert_key_pair():
    """Generate a self-signed certificate and its matching private key (PEM bytes)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "test.local")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def test_e2e_round_trip_same_apikey():
    """A payload encrypted by one side decrypts on the other with the same API key."""
    apikey = "secret-key"
    server_priv, server_pub = crypto.generate_ephemeral_keypair()
    client_priv, client_pub = crypto.generate_ephemeral_keypair()

    server_key = crypto.derive_shared_key(server_priv, client_pub, apikey)
    client_key = crypto.derive_shared_key(client_priv, server_pub, apikey)
    assert server_key == client_key

    plaintext = b"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"
    nonce, ciphertext = crypto.encrypt_payload(server_key, plaintext)
    assert crypto.decrypt_payload(client_key, nonce, ciphertext) == plaintext


def test_e2e_wrong_apikey_cannot_decrypt():
    """A different API key derives a different key, so decryption fails."""
    server_priv, server_pub = crypto.generate_ephemeral_keypair()
    client_priv, client_pub = crypto.generate_ephemeral_keypair()

    server_key = crypto.derive_shared_key(server_priv, client_pub, "real-key")
    attacker_key = crypto.derive_shared_key(client_priv, server_pub, "wrong-key")
    assert server_key != attacker_key

    nonce, ciphertext = crypto.encrypt_payload(server_key, b"top secret")
    with pytest.raises(Exception):
        crypto.decrypt_payload(attacker_key, nonce, ciphertext)


def test_challenge_sign_verify_round_trip():
    """A signed challenge verifies with the same secret."""
    secret = b"server-secret-bytes"
    nonce_b64 = base64.b64encode(b"x" * 32).decode()
    sig = crypto.sign_challenge(secret, nonce_b64, 1000)
    assert crypto.verify_challenge(secret, nonce_b64, 1000, sig) is True


def test_challenge_verify_fails_on_tamper():
    """Tampered fields or a rotated secret fail verification."""
    secret = b"server-secret-bytes"
    nonce_b64 = base64.b64encode(b"x" * 32).decode()
    sig = crypto.sign_challenge(secret, nonce_b64, 1000)
    assert crypto.verify_challenge(secret, nonce_b64, 1001, sig) is False
    assert crypto.verify_challenge(b"other-secret", nonce_b64, 1000, sig) is False


def test_proof_verify_matches_configured_key():
    """A proof computed with a configured key is accepted and returns that key."""
    nonce_b64 = base64.b64encode(b"y" * 32).decode()
    client_pub_b64 = base64.b64encode(b"z" * 32).decode()
    proof = crypto.compute_proof("k2", "GET", "/cert", nonce_b64, 5, client_pub_b64)
    matched = crypto.verify_proof(
        proof, ["k1", "k2", "k3"], "GET", "/cert", nonce_b64, 5, client_pub_b64
    )
    assert matched == "k2"


def test_proof_path_binding():
    """A proof minted for /cert is rejected when presented on /privkey."""
    nonce_b64 = base64.b64encode(b"y" * 32).decode()
    client_pub_b64 = base64.b64encode(b"z" * 32).decode()
    proof = crypto.compute_proof("k1", "GET", "/cert", nonce_b64, 5, client_pub_b64)
    assert (
        crypto.verify_proof(
            proof, ["k1"], "GET", "/privkey", nonce_b64, 5, client_pub_b64
        )
        is None
    )


def test_proof_pubkey_binding():
    """A proof is bound to the client's public key."""
    nonce_b64 = base64.b64encode(b"y" * 32).decode()
    pub_a = base64.b64encode(b"a" * 32).decode()
    pub_b = base64.b64encode(b"b" * 32).decode()
    proof = crypto.compute_proof("k1", "GET", "/cert", nonce_b64, 5, pub_a)
    assert (
        crypto.verify_proof(proof, ["k1"], "GET", "/cert", nonce_b64, 5, pub_b) is None
    )


def test_proof_no_matching_key():
    """A proof with an unknown key returns None."""
    nonce_b64 = base64.b64encode(b"y" * 32).decode()
    client_pub_b64 = base64.b64encode(b"z" * 32).decode()
    proof = crypto.compute_proof("unknown", "GET", "/cert", nonce_b64, 5, client_pub_b64)
    assert (
        crypto.verify_proof(
            proof, ["k1", "k2"], "GET", "/cert", nonce_b64, 5, client_pub_b64
        )
        is None
    )


def test_cert_key_match_true():
    """A coherent cert/key pair matches."""
    cert_pem, key_pem = _make_cert_key_pair()
    assert crypto.cert_key_match(cert_pem, key_pem) is True


def test_cert_key_match_false():
    """A cert paired with a foreign key does not match."""
    cert_pem, _ = _make_cert_key_pair()
    _, other_key_pem = _make_cert_key_pair()
    assert crypto.cert_key_match(cert_pem, other_key_pem) is False


def test_cert_key_match_invalid_input():
    """Unparseable input raises ValueError."""
    with pytest.raises(ValueError):
        crypto.cert_key_match(b"not a cert", b"not a key")
