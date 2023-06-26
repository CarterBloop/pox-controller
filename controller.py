from pox.core import core
import pox.openflow.libopenflow_01 as of
log = core.getLogger()
class Firewall (object):
    """
    A Firewall object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__ (self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection
        # This binds our PacketIn event listener
        connection.addListeners(self)
    def do_firewall (self, packet, packet_in):
        # Match
        match_obj = of.ofp_match()
        match_obj.dl_type = packet.type # Packet properties
        if packet.type == packet.IP_TYPE:
            match_obj.nw_proto = packet.next.protocol
            match_obj.nw_src = packet.next.srcip
            match_obj.nw_dst = packet.next.dstip

        # Actions
        message = of.ofp_flow_mod() # "Installs" rule on switch
        message.match = match_obj

        # Allow TCP/ARP traffic
        if (packet.type == packet.IP_TYPE and packet.next.protocol ==
            packet.next.TCP_PROTOCOL) or (packet.type == packet.ARP_TYPE):
            action = of.ofp_action_output(port = of.OFPP_ALL)
            message.actions.append(action)
        # Drop all other packets/traffic
        else:
            message.actions = []

        self.connection.send(message)
        return
    def _handle_PacketIn (self, event):
        """
        Handles packet in messages from the switch.
        """
        packet = event.parsed # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        packet_in = event.ofp # The actual ofp_packet_in message.
        self.do_firewall(packet, packet_in)
    def launch ():
        """
        Starts the component
        """
        def start_switch (event):
            log.debug("Controlling %s" % (event.connection,))
            Firewall(event.connection)
        core.openflow.addListenerByName("ConnectionUp", start_switch)

