from pox.core import core

from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ETHER_BROADCAST, ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.recoco import Timer

import pox.openflow.libopenflow_01 as of


log = core.getLogger("iplb")

CLIENT_GW_IP = IPAddr("10.0.1.1")
CLIENT_GW_MAC = EthAddr("00:00:00:00:00:11")
SERVER_GW_IP = IPAddr("20.0.1.1")
SERVER_GW_MAC = EthAddr("00:00:00:00:01:11")
SERVICE_IP = IPAddr("20.0.1.2")
SERVER_MACS = {
  IPAddr("20.0.0.1"): EthAddr("00:00:00:00:01:01"),
  IPAddr("20.0.0.2"): EthAddr("00:00:00:00:01:02"),
  IPAddr("20.0.0.3"): EthAddr("00:00:00:00:02:01"),
}

# bk: network capacity of each server in bps
SERVER_CAPACITY = {
  IPAddr("20.0.0.1"): 1_000_000,
  IPAddr("20.0.0.2"): 1_000_000,
  IPAddr("20.0.0.3"): 1_000_000,
}

# di: traffic demand per request in bps
SERVICE_DEMAND = 100_000


class iplb(object):
  def __init__(self, connection, service_ip, servers=None):
    if servers is None:
      servers = []

    self.con = connection
    self.service_ip = IPAddr(service_ip)
    self.servers = [IPAddr(server) for server in servers]
    self.hosts = {}
    self.server_to_client = {}
    self.connection_to_server = {}
    self.server_load = {IPAddr(s): 0 for s in servers}

    for server_ip, server_mac in SERVER_MACS.items():
      self.hosts[server_ip] = (server_mac, None)

    self.con.addListeners(self)
    self.install_controller_flows()
    Timer(5, self._log_loads, recurring=True)

  def install_controller_flows(self):
    arp_msg = of.ofp_flow_mod()
    arp_msg.priority = 100
    arp_msg.match.dl_type = ethernet.ARP_TYPE
    arp_msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    self.con.send(arp_msg)

    ip_msg = of.ofp_flow_mod()
    ip_msg.priority = 90
    ip_msg.match.dl_type = ethernet.IP_TYPE
    ip_msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    self.con.send(ip_msg)

  def _log_loads(self):
    for server_ip in self.servers:
      n = self.server_load.get(server_ip, 0)
      b = SERVER_CAPACITY.get(server_ip, 1)
      rho = (n * SERVICE_DEMAND) / b
      log.info("Server %s: active_connections=%s, rho(t)=%.4f", server_ip, n, rho)

  def get_server_load(self, server_ip):
    return self.server_load.get(IPAddr(server_ip), 0)

  def _remember_host(self, ip_addr, mac_addr, port):
    self.hosts[IPAddr(ip_addr)] = (EthAddr(mac_addr), port)

  def _reply_arp(self, event, arp_req, reply_mac):
    arp_reply = arp()
    arp_reply.hwtype = arp_req.hwtype
    arp_reply.prototype = arp_req.prototype
    arp_reply.hwlen = arp_req.hwlen
    arp_reply.protolen = arp_req.protolen
    arp_reply.opcode = arp.REPLY
    arp_reply.hwsrc = reply_mac
    arp_reply.hwdst = arp_req.hwsrc
    arp_reply.protosrc = arp_req.protodst
    arp_reply.protodst = arp_req.protosrc

    eth = ethernet()
    eth.type = ethernet.ARP_TYPE
    eth.src = reply_mac
    eth.dst = arp_req.hwsrc
    eth.payload = arp_reply

    msg = of.ofp_packet_out()
    msg.data = eth.pack()
    msg.actions.append(of.ofp_action_output(port=event.port))
    self.con.send(msg)

  def _least_loaded_server(self):
    min_rho = float('inf')
    least_loaded_index = 0
    for i, server in enumerate(self.servers):
      n = self.server_load.get(server, 0)
      b = SERVER_CAPACITY.get(server, 1)
      rho = (n * SERVICE_DEMAND) / b
      if rho < min_rho:
        min_rho = rho
        least_loaded_index = i
    return least_loaded_index

  def _next_server(self):
    if not self.servers:
      return None
    return self.servers[self._least_loaded_server()]

  def _forward_to_server(self, event, packet, ip_packet):
    client_state = self.hosts.get(ip_packet.srcip)
    if client_state is None:
      log.warn("Unknown client %s", ip_packet.srcip)
      return

    # Always select the least-loaded server for each request (no session persistence)
    tcp_packet = ip_packet.find('tcp')
    if tcp_packet is not None:
      conn_key = (ip_packet.srcip, tcp_packet.srcport)
      server_ip = self.connection_to_server.get(conn_key)
      if server_ip is None:
        server_ip = self._next_server()
        if server_ip is None:
          log.warn("No backend servers configured")
          return
        self.connection_to_server[conn_key] = server_ip
        self.server_load[server_ip] = self.server_load.get(server_ip, 0) + 1
      if tcp_packet.FIN or tcp_packet.RST:
        self.connection_to_server.pop(conn_key, None)
        self.server_load[server_ip] = max(0, self.server_load.get(server_ip, 0) - 1)
    else:
      server_ip = self._next_server()
      if server_ip is None:
        log.warn("No backend servers configured")
        return
      self.server_load[server_ip] = self.server_load.get(server_ip, 0) + 1

    # Store the mapping for reply routing
    self.server_to_client[(server_ip, ip_packet.srcip)] = ip_packet.srcip

    server_state = self.hosts.get(server_ip)
    if server_state is None:
      log.warn("Server %s has not been learned yet", server_ip)
      return

    server_mac, server_port = server_state
    client_mac, client_port = client_state

    msg = of.ofp_packet_out(data=event.ofp)
    msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
    msg.actions.append(of.ofp_action_dl_addr.set_src(SERVER_GW_MAC))
    msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
    msg.actions.append(of.ofp_action_output(port=server_port if server_port is not None else of.OFPP_FLOOD))
    self.con.send(msg)

    rho = (self.server_load.get(server_ip, 0) * SERVICE_DEMAND) / SERVER_CAPACITY.get(server_ip, 1)
    log.info("Forwarded %s -> %s via %s (n=%s, rho=%.4f)", ip_packet.srcip, self.service_ip, server_ip, self.server_load.get(server_ip, 0), rho)

  def _forward_to_client(self, event, packet, ip_packet):
    client_ip = self.server_to_client.get((ip_packet.srcip, ip_packet.dstip))
    if client_ip is None:
      log.warn("No client mapping for reply %s -> %s", ip_packet.srcip, ip_packet.dstip)
      return

    client_state = self.hosts.get(client_ip)
    if client_state is None:
      log.warn("Client %s has not been learned yet", client_ip)
      return

    client_mac, client_port = client_state

    msg = of.ofp_packet_out(data=event.ofp)
    msg.actions.append(of.ofp_action_dl_addr.set_src(CLIENT_GW_MAC))
    msg.actions.append(of.ofp_action_dl_addr.set_dst(client_mac))
    msg.actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
    msg.actions.append(of.ofp_action_output(port=client_port))
    self.con.send(msg)

    log.debug("Forwarded %s -> %s back to client %s", ip_packet.srcip, ip_packet.dstip, client_ip)

  def _handle_PacketIn(self, event):
    packet = event.parsed
    if not packet.parsed:
      return

    if packet.type == ethernet.ARP_TYPE:
      arp_packet = packet.payload
      self._remember_host(arp_packet.protosrc, arp_packet.hwsrc, event.port)

      if arp_packet.opcode != arp.REQUEST:
        return

      if arp_packet.protodst == CLIENT_GW_IP:
        self._reply_arp(event, arp_packet, CLIENT_GW_MAC)
        return

      if arp_packet.protodst == SERVER_GW_IP:
        self._reply_arp(event, arp_packet, SERVER_GW_MAC)
        return

      return

    if packet.type != ethernet.IP_TYPE:
      return

    ip_packet = packet.find('ipv4')
    if ip_packet is None:
      return

    if ip_packet.dstip == self.service_ip:
      self._forward_to_server(event, packet, ip_packet)
      return

    if ip_packet.srcip in self.servers:
      self._forward_to_client(event, packet, ip_packet)


def launch():
  def start_iplb(event):
    iplb(event.connection, SERVICE_IP, ["20.0.0.1", "20.0.0.2", "20.0.0.3"])
    log.info("Controlling %s", event.connection)

  core.openflow.addListenerByName("ConnectionUp", start_iplb)
