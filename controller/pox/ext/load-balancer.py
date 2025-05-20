from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import IPAddr
from pox.openflow import libopenflow_01 as of
from routing_algorithm import get_next_hop  # Import the external algorithm

log = core.getLogger()

class LoadBalancer(object):
    def __init__(self):
        log.info("Initializing Load Balancer")
        core.openflow.addListeners(self)

    def _handle_PacketIn(self, event):
        """
        Handles incoming packets and routes them based on the external algorithm.
        """
        packet = event.parsed

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Check if the packet is an IPv4 packet
        if packet.type == ethernet.IP_TYPE:
            ip_packet = packet.payload

            if isinstance(ip_packet, ipv4):
                log.info(f"Packet received from {ip_packet.srcip} to {ip_packet.dstip}")

                # Use the external algorithm to determine the next hop
                next_hop = get_next_hop(str(ip_packet.srcip), str(ip_packet.dstip))

                if next_hop:
                    log.info(f"Routing packet to {next_hop}")

                    # Modify the destination IP
                    ip_packet.dstip = IPAddr(next_hop)

                    # Create a new packet to send
                    new_packet = ethernet()
                    new_packet.src = packet.src
                    new_packet.dst = packet.dst
                    new_packet.type = packet.type
                    new_packet.payload = ip_packet

                    # Send the modified packet out
                    msg = of.ofp_packet_out()
                    msg.data = new_packet.pack()
                    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                    event.connection.send(msg)
                    return

        # If the packet doesn't match, flood it
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

def launch():
    """
    Launches the POX controller.
    """
    log.info("Starting POX Load Balancer Controller")
    LoadBalancer()