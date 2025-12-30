# Part 2 of UWCSE's Mininet-SDN project2
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp

# TODO:请完成s1_setup，s2_setup，s3_setup，cores21_setup，dcs31_setup的编写（与part3相似）
# 自定义函数实现学习型路由器
# 请注意可能需要引入新的包
# 需要对_handle_PacketIn函数进行修改


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


class Part4Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection
        
        # ARP Table: IPAddr -> (EthAddr, Port)
        self.arp_table = {}

        # Gateway MAC Address
        self.gw_mac = EthAddr("00:00:00:00:00:FE")

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
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg)

    def s2_setup(self):
        # Flood all packets
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg)

    def s3_setup(self):
        # Flood all packets
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg)

    def cores21_setup(self):
        # put core switch rules here
        # Firewall policies
        
        # 1. Block all IP traffic from hnotrust1 subnet to serv1
        msg = of.ofp_flow_mod()
        msg.priority = 200 # Higher than default
        msg.match.dl_type = 0x0800 # IP
        msg.match.nw_src = SUBNETS["hnotrust"]
        msg.match.nw_dst = IPS["serv1"]
        # No actions -> Drop
        self.connection.send(msg)
        msg = of.ofp_flow_mod()
        msg.priority = 200
        msg.match.dl_type = 0x0800 # IP
        msg.match.nw_proto = 1 # ICMP
        msg.match.nw_src = SUBNETS["hnotrust"]
        # No actions -> Drop
        self.connection.send(msg)
    def dcs31_setup(self):
        # Flood all packets
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg)

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
        
        if self.connection.dpid == 21:
            self.handle_cores21_packet(event)
        else:
            # Should not happen for s1, s2, s3, dcs31 as they have flood rules
            pass

    def handle_cores21_packet(self, event):
        packet = event.parsed
        in_port = event.port
        
        # Learn from source
        if packet.type == ethernet.IP_TYPE:
            ip_packet = packet.payload
            self.arp_table[ip_packet.srcip] = (packet.src, in_port)
        elif packet.type == ethernet.ARP_TYPE:
            arp_packet = packet.payload
            self.arp_table[arp_packet.protosrc] = (packet.src, in_port)
            
            if arp_packet.opcode == arp.REQUEST:
                # Check if it is for a gateway
                # Gateways: 10.0.1.1, 10.0.2.1, 10.0.3.1, 10.0.4.1, 172.16.10.1
                gateways = [IPAddr("10.0.1.1"), IPAddr("10.0.2.1"), IPAddr("10.0.3.1"), IPAddr("10.0.4.1"), IPAddr("172.16.10.1")]
                
                if arp_packet.protodst in gateways:
                    # Reply
                    reply = arp()
                    reply.opcode = arp.REPLY
                    reply.hwdst = arp_packet.hwsrc
                    reply.protodst = arp_packet.protosrc
                    reply.hwsrc = self.gw_mac # Router MAC
                    reply.protosrc = arp_packet.protodst
                    
                    eth = ethernet()
                    eth.type = ethernet.ARP_TYPE
                    eth.dst = packet.src
                    eth.src = self.gw_mac
                    eth.payload = reply
                    
                    self.resend_packet(eth.pack(), in_port)
                    return

        # Forward IP
        if packet.type == ethernet.IP_TYPE:
            ip_packet = packet.payload
            dst_ip = ip_packet.dstip
            
            if dst_ip in self.arp_table:
                dst_mac, out_port = self.arp_table[dst_ip]
                
                # Install flow
                msg = of.ofp_flow_mod()
                msg.match.dl_type = 0x0800
                msg.match.nw_dst = dst_ip
                msg.priority = 100
                
                # Actions: Set Src MAC (Router), Set Dst MAC (Host), Output
                msg.actions.append(of.ofp_action_dl_addr.set_src(self.gw_mac))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
                msg.actions.append(of.ofp_action_output(port = out_port))
                self.connection.send(msg)
                
                # Send this packet
                # We need to apply the same actions to the packet we are forwarding
                packet.src = self.gw_mac
                packet.dst = dst_mac
                self.resend_packet(packet.pack(), out_port)
            else:
                # Drop (do nothing)
                # print("Dropping packet for unknown destination: " + str(dst_ip))
                pass


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part4Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
