import socket
import ssl


class TLSSocketWrapper:
    def __init__(self, server_hostname, check_hostname=False, verify_mode=ssl.CERT_NONE,
                 minimum_version=ssl.TLSVersion.TLSv1_2, maximum_version=ssl.TLSVersion.TLSv1_3,
                 cipher_suite='ECDHE-RSA-AES128-GCM-SHA256'):
        self.server_hostname = server_hostname
        self.check_hostname = check_hostname
        self.verify_mode = verify_mode
        self.minimum_version = minimum_version
        self.maximum_version = maximum_version
        self.cipher_suite = cipher_suite

    def create_sock(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = self.check_hostname

        context.verify_mode = self.verify_mode
        context.minimum_version = self.minimum_version

        context.maximum_version = self.maximum_version
        context.set_ciphers(self.cipher_suite)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client = context.wrap_socket(s, server_hostname=self.server_hostname)

        return client


if __name__ == "__main__":
    tls_wrapper = TLSSocketWrapper("mad.cyberoffensive.org")
    client_socket = tls_wrapper.create_sock()

    # Do your communication using client_socket

    client_socket.close()
