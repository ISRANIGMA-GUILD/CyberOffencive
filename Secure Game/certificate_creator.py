from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import *
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

H_NAME = "Cyber-Offensive"
KEY_ENC = serialization.Encoding.X962
FORMAT_PUBLIC = serialization.PublicFormat.UncompressedPoint
THE_PEM = serialization.Encoding.PEM
PRIVATE_OPENSSL = serialization.PrivateFormat.TraditionalOpenSSL
GOOD_PAD = PSS(MGF1(hashes.SHA256()), PSS.MAX_LENGTH)
MAX_MSG_LENGTH = 1024
THE_SHA_256 = hashes.SHA256()
SECP = 0x0017
SIGNATURE_ALGORITHIM = 0x0401


for index in range(0, 20):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    names = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, H_NAME)])
    basic_constraints = x509.BasicConstraints(ca=True, path_length=0)

    now = datetime.utcnow()
    key_usage = x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                              data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                              encipher_only=False, decipher_only=False)

    ext_usage = x509.ExtendedKeyUsage((x509.OID_SERVER_AUTH, x509.OID_CLIENT_AUTH))
    number = x509.random_serial_number()
    cert = (x509.CertificateBuilder()
            .subject_name(names)
            .issuer_name(names)
            .public_key(key.public_key())
            .serial_number(number)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(basic_constraints, True)
            .add_extension(key_usage, True)
            .add_extension(ext_usage, True)
            .sign(key, THE_SHA_256, default_backend(), rsa_padding=PKCS1v15())
            )

    my_cert_pem = cert.public_bytes(encoding=THE_PEM)
    my_key_pem = key.private_bytes(encoding=THE_PEM, format=serialization.PrivateFormat.PKCS8,
                                   encryption_algorithm=serialization
                                   .BestAvailableEncryption(b'gfdgdfgdhffdgfdgfdgdf'))

    with open(f'Certificates\\Certificate_crts\\certifacte{index}.crt', 'wb') as certificate_first:
        certificate_first.write(my_cert_pem)

    with open(f'Certificates\\certifacte{index}.pem', 'wb') as certificate_first:
        certificate_first.write(my_cert_pem)

    with open(f'Keys\\the_key{index}.pem', 'wb') as key_first:
        key_first.write(my_key_pem)
