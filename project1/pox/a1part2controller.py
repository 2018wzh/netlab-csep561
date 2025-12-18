# Part 2 of UWCSE's Project 3
#
# based on Lab 4 from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()


class Firewall(object):
    """
    A Firewall object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # TODO
        # add switch rules here

        # Rule1: anyv4,anyv4,icmp,accept
        rule1 = of.ofp_flow_mod()
        rule1.priority = 100
        rule1.match.dl_type = 0x800  # IPv4 packets
        rule1.match.nw_proto = 1  # ICMP protocol
        rule1.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        self.connection.send(rule1)

        # Rule2: any,any,arp,accept
        rule2 = of.ofp_flow_mod()
        rule2.priority = 90
        rule2.match.dl_type = 0x806  # ARP packets
        rule2.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        self.connection.send(rule2)

        # Rule3: anyv4,anyv4,*,drop
        rule3 = of.ofp_flow_mod()
        rule3.priority = 80
        rule3.match.dl_type = 0x800  # IPv4 packets
        # No actions = drop
        self.connection.send(rule3)



    def _handle_PacketIn(self, event):
        """
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        """

        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.
        print("Unhandled packet :" + str(packet.dump()))


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Firewall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
