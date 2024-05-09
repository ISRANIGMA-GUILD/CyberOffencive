import ssl

import select


class Selector:

    def __init__(self, server: ssl.SSLSocket, client_sockets: list, logs: list):
        self.__client_sockets = client_sockets
        self.__logs = logs
        self.__server = server
        self.__selector = select.select([self.__server] + self.__client_sockets,
                                        self.__client_sockets + self.__logs, [])
        pass

    def run(self):

        return self.__selector

    def the_sock(self):

        return self.__server



