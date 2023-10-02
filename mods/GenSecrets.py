from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from . import ConfigParserCrypt as configparser
from cryptography import x509
import datetime
import os
import sys


def _get_parser():
    # Let's get the configuration file and read it
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config.ini'))
    config = configparser.ConfigParserCrypt()
    return config.config_read(config_path)


def generate_es256_keys():
    """
    Generate ES256 (ECDSA using P-256 and SHA-256) keys.

    :return: private_key, public_key both in PEM format.
    """
    # Generate a private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generate the associated public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def generate_self_signed_cert():
    """
        Generate a self-signed certificate.
    """
    if "DRIP_SECRET" not in os.environ:
        print("Please set the DRIP_SECRET environment variable.")
        sys.exit(1)

    # Fetch the passphrase from the environment
    passphrase = os.environ["DRIP_SECRET"].encode('utf-8')

    # Get the parser
    parser = _get_parser()

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME,  parser.get('gRPC_Certificate', 'common_name')),
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, parser.get('gRPC_Certificate', 'country_name')),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, parser.get('gRPC_Certificate', 'organization_name')),
        x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, parser.get('gRPC_Certificate', 'email_address')),
    ])

    san = x509.SubjectAlternativeName([
        x509.DNSName(parser.get('gRPC_Certificate', 'san_dns_1')),
        x509.DNSName(parser.get('gRPC_Certificate', 'san_dns_2')),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=parser.getint('gRPC_Certificate', 'validity_days'))
    ).add_extension(
        san, critical=False
    ).sign(key, hashes.SHA256(), default_backend())

    server_cert_pem_name = parser.get('gRPC_Certificate', 'server_cert_name')
    server_cert_pem_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', server_cert_pem_name))
    with open(server_cert_pem_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    server_cert_key_name = parser.get('gRPC_Certificate', 'server_key_name')   
    server_cert_key_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', server_cert_key_name))
    with open(server_cert_key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=BestAvailableEncryption(passphrase)
        ))
