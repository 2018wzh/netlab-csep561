# Part 1 of UWCSE's Mininet-SDN project2
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

#TODO:请完成s1_setup，s2_setup，s3_setup，cores21_setup，dcs31_setup的编写
#请注意可能需要引入新的包


log = core.getLogger()

# Convenience mappings of hostnames to ips
IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

# Convenience mappings of hostnames to subnets
SUBNETS = {
    "h10": "10.0.1.0/24",
    "h20": "10.0.2.0/24",
    "h30": "10.0.3.0/24",
    "serv1": "10.0.4.0/24",
    "hnotrust": "172.16.10.0/24",
}


class Part3Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)
        # use the dpid to figure out what switch is being created
        if connection.dpid == 1:
            self.s1_setup()
        elif connection.dpid == 2:
            self.s2_setup()
        elif connection.dpid == 3:
            self.s3_setup()
        elif connection.dpid == 21:
            self.cores21_setup()
        elif connection.dpid == 31:
            self.dcs31_setup()
        else:
            print("UNKNOWN SWITCH")
            exit(1)

    def s1_setup(self):
        # Flood all packets
        rule = of.ofp_flow_mod()
        rule.priority = 100
        rule.match.dl_type = 0x800  # IPv4 packets
        rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(rule)


    def s2_setup(self):
        # Flood all packets
        rule = of.ofp_flow_mod()
        rule.priority = 100
        rule.match.dl_type = 0x800  # IPv4 packets
        rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(rule)

    def s3_setup(self):
        # Flood all packets
        rule = of.ofp_flow_mod()
        rule.priority = 100
        rule.match.dl_type = 0x800  # IPv4 packets
        rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(rule)

    def cores21_setup(self):
        # Route packets to h10
        rule1 = of.ofp_flow_mod()
        rule1.priority = 100
        rule1.match.nw_dst = SUBNETS["h10"]
        rule1.match.dl_type = 0x800  # IPv4 packets
        rule1.actions.append(of.ofp_action_output(port=1))
        self.connection.send(rule1)
        # Route packets to h20
        rule2 = of.ofp_flow_mod()
        rule2.priority = 100
        rule2.match.nw_dst = SUBNETS["h20"]
        rule2.match.dl_type = 0x800  # IPv4 packets
        rule2.actions.append(of.ofp_action_output(port=2))
        self.connection.send(rule2)
        # Route packets to h30
        rule3 = of.ofp_flow_mod()
        rule3.priority = 100
        rule3.match.nw_dst = SUBNETS["h30"]
        rule3.match.dl_type = 0x800  # IPv4 packets
        rule3.actions.append(of.ofp_action_output(port=3))
        self.connection.send(rule3)
        # Route packets to serv1
        rule4 = of.ofp_flow_mod()
        rule4.priority = 100
        rule4.match.nw_dst = SUBNETS["serv1"]
        rule4.match.dl_type = 0x800  # IPv4 packets
        rule4.actions.append(of.ofp_action_output(port=4))
        self.connection.send(rule4)
        # Route packets to hnotrust
        rule5 = of.ofp_flow_mod()
        rule5.priority = 100
        rule5.match.nw_dst = SUBNETS["hnotrust"]
        rule5.match.dl_type = 0x800  # IPv4 packets
        rule5.actions.append(of.ofp_action_output(port=5))
        self.connection.send(rule5)
        # Block all packets from hnotrust to serv1
        rule6 = of.ofp_flow_mod()
        rule6.match.nw_src = SUBNETS["hnotrust"]
        rule6.match.nw_dst = SUBNETS["serv1"]
        rule6.match.dl_type = 0x800  # IPv4 packets
        rule6.priority = 200  # Higher priority
        # No actions means drop the packet
        self.connection.send(rule6)
        # Block ICMP packets from hnotrust to any other subnet
        rule7 = of.ofp_flow_mod()
        rule7.match.dl_type = 0x0800  # IP packets
        rule7.match.nw_proto = 1  # ICMP protocol
        rule7.match.nw_src = SUBNETS["hnotrust"]
        rule7.priority = 200  # Higher priority
        # No actions means drop the packet
        self.connection.send(rule7)

    def dcs31_setup(self):
        # Flood all packets
        rule = of.ofp_flow_mod()
        rule.priority = 100
        rule.match.dl_type = 0x800  # IPv4 packets
        rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(rule)

    # used in part 4 to handle individual ARP packets
    # not needed for part 3 (USE RULES!)
    # causes the switch to output packet_in on out_port
    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

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
        print(
            "Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump()
        )


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
