from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import *
from cryptography.hazmat.primitives.asymmetric.padding import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from scapy.all import *
import os
import string

H_NAME = "Cyber-Offensive"
D_NAME = "mad.cyberoffensive.org"
KEY_ENC = serialization.Encoding.X962
FORMAT_PUBLIC = serialization.PublicFormat.UncompressedPoint
THE_PEM = serialization.Encoding.PEM
PRIVATE_OPENSSL = serialization.PrivateFormat.TraditionalOpenSSL
GOOD_PAD = PSS(MGF1(hashes.SHA256()), PSS.MAX_LENGTH)
MAX_MSG_LENGTH = 1024
THE_SHA_256 = hashes.SHA256()
SECP = 0x0017
SIGNATURE_ALGORITHIM = 0x0401
MY_IP = conf.route.route('0.0.0.0')[1]
COUNTRY_NAMES = [u"UG", u"SO", u"US", u"NO", u"NE", u"IL", u"IN", u"DE", u"FR", u"TX", u"MG", u"IE", u"RU", u"PL",
                 u"NL", u"MZ", u"KP", u"CN", u"CI", u"SD", u"IR", u"VA", u"GL", u"PS"]
PROVINCES = [u"Llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch", u"Bronitzki", u"SPIKES#2212", u"Ohio",
             u"California", u"Brandenburg", u"Hawaii", u"Texas", u"Alabama", u"OS", u"Lod", u"Um-El-Faheem", u"Yakutsk",
             u"Westphalia", u"Vladivostok", u"Siberia", u"Alsace-Lorraine", u"Bavaria", u"Schleswig-Holstein",
             u"Brittany", u"Maputo", u"KIM-JON-UN", u"Tibet", u"Taipei", u"Negev", u"None", u"NewFoundLand"]
LOCALITIES = [u"Nambia", u"Socretesus", u"Jerusalem", u"Chicago", u"Atlantis", u"Paris", u"Tokyo", u"Antananarivo",
              u"Shoham", u"Jenin", u"Hawara", u"Gaza", u"Rafah", u"Eilat", "Tehran", u"Moscow", u"Stockholm",
              u"Amsterdam", u"Rotterdam", u"St. Petersburg", u"Stalingrad", u"Leningrad", u"China-Wall-Street",
              u"Toulon", u"London", u"Dublin", u"Alexandria", u"Warsaw", u"Pyongyang", u"Beijing", u"Yamoussoukro",
              u"Kampala", u"Vatican-City", u"Nuuk"]


class CertificateCreator:

    def __init__(self, pathname):
        self.__passes = []
        self.__path = pathname
        pass

    def run(self):
        """

        :return:
        """

        for index in range(0, 20):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

            random_number = random.randint(0, 23)
            random_number_s = random.randint(0, 26)

            random_number_l = random.randint(0, 33)
            c_name = COUNTRY_NAMES[random_number]

            s_name = PROVINCES[random_number_s]
            l_name = LOCALITIES[random_number_l]

            names = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, c_name),
                               x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, s_name),
                               x509.NameAttribute(NameOID.LOCALITY_NAME, l_name),
                               x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ISRA-NIGMA-GUILD"),
                               x509.NameAttribute(NameOID.COMMON_NAME, H_NAME)])
            basic_constraints = x509.BasicConstraints(ca=True, path_length=0)

            now = datetime.utcnow()
            key_usage = x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                                      encipher_only=False, decipher_only=False)

            alt_names = [x509.DNSName(D_NAME), x509.DNSName(MY_IP)]
            password = self.random_password()

            self.__passes.append(password)
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
                    .add_extension(x509.SubjectAlternativeName(alt_names), False)
                    .sign(key, THE_SHA_256, default_backend(), rsa_padding=PKCS1v15())
                    )

            my_cert_pem = cert.public_bytes(encoding=THE_PEM)
            my_key_pem = key.private_bytes(encoding=THE_PEM, format=serialization.PrivateFormat.PKCS8,
                                           encryption_algorithm=serialization
                                           .BestAvailableEncryption(password.encode()))

            with (open(f'{self.__path}_Certificates\\Certificate_crts\\certificate{index}.crt', 'wb') as
                  certificate_first):
                certificate_first.write(my_cert_pem)

            with open(f'{self.__path}_Certificates\\certificate{index}.pem', 'wb') as certificate_first:
                certificate_first.write(my_cert_pem)

            with open(f'{self.__path}_Keys\\the_key{index}.pem', 'wb') as key_first:
                key_first.write(my_key_pem)

        return self.__passes

    def random_password(self):
        """
         "Hhehehe password go brrrrrrrrrrr" -Someone at 5AM
        :return:
        """

        chars = string.ascii_letters + string.digits + '+/'
        assert 256 % len(chars) == 0  # non-biased later modulo

        password_length = 256
        password = ''.join(chars[c % len(chars)] for c in os.urandom(password_length))

        return password
