from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str
from pox.openflow import libopenflow_01 as of

log = core.getLogger()

# Define the source and destination IPs
SOURCE_IP = "10.0.0.1"
DESTINATION_IP = "30.0.0.1"

class loadbalancer(object):
    def _handle_PacketIn(event):
        """
        Handles incoming packets and forwards packets from SOURCE_IP to DESTINATION_IP.
        """
        packet = event.parsed

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Check if the packet is an IPv4 packet
        if packet.type == ethernet.IP_TYPE:
            ip_packet = packet.payload

            if isinstance(ip_packet, ipv4) and ip_packet.srcip == IPAddr(SOURCE_IP):
                log.info(f"Packet received from {SOURCE_IP}, redirecting to {DESTINATION_IP}")

                # Modify the destination IP
                ip_packet.dstip = IPAddr(DESTINATION_IP)

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
    core.openflow.addListeners(loadbalancer._handle_PacketIn)