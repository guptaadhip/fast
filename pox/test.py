from pox.core import core
import pox.openflow.nicira as nx
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ethernet
import time

log = core.getLogger()

class Fast(object):
    def __init__ (self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.info("Adhip: I am up");
        # Initialize Nicira
        msg = nx.nx_flow_mod()
        event.connection.send(msg)
        
        # Signal Table use 
        msg = nx.nx_flow_mod_table_id()
        event.connection.send(msg)

        #Table 1 -> PING Table 2 -> ARP 
        msg = nx.nx_flow_mod(command=of.OFPFC_DELETE, table_id = 1)
        event.connection.send(msg)
    
        msg = nx.nx_flow_mod(command=of.OFPFC_DELETE, table_id = 2)
        event.connection.send(msg)
      
        #Table 0 rule: Selection of tables
        #IP Packet Handling
        msg = nx.nx_flow_mod()
        msg.match.eth_type = ethernet.IP_TYPE
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 1))
        event.connection.send(msg) 
        #ARP Packet Handling
        msg = nx.nx_flow_mod()
        msg.priority = 65001
        msg.match.eth_type = pkt.ethernet.ARP_TYPE
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 2))
        event.connection.send(msg)
        msg = nx.nx_flow_mod()
        msg.match.eth_type = ethernet.IP_TYPE
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        event.connection.send(msg) 
        #log.info("Table 0 done %d" % pkt.ipv4.ICMP_TYPE)
       
        #Table 1 Rules
        msg = nx.nx_flow_mod()
        msg.table_id = 1
        #msg.match.of_ip_dst_with_mask = ("0.0.0.1","0.0.0.255")
        #msg.match.ip_dst = "10.0.0.1"
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        #msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        event.connection.send(msg)
        log.info("Table 1a done")

        #msg = nx.nx_flow_mod()
        #msg.table_id = 1
        #msg.match.of_ip_dst_with_mask = ("0.0.0.2","0.0.0.255")
        #msg.match.ip_dst = "10.0.0.2"
        #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        #event.connection.send(msg)
        #log.info("Table 1b done")

        #msg = nx.nx_flow_mod()
        #msg.table_id = 1
        #msg.match.of_ip_dst_with_mask = ("0.0.0.3","0.0.0.255")
        #msg.match.ip_dst = "10.0.0.3"
        #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        #event.connection.send(msg)
        #log.info("Table 1c done")

        #Table 2 Rules 
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)
        log.info("Table 2 done")
        
        #Ping code 
        #msg = of.ofp_flow_mod()
        #msg.match.dl_type = 0x0806
        #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        #event.connection.send(msg)
        #msg = of.ofp_flow_mod()
        #msg.match.nw_dst = IPAddr("10.0.0.1")
        #msg.match.dl_type = 0x0800
        #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        #event.connection.send(msg)
        #log.info("Adhip: 1 flow sent")
        #msg1 = of.ofp_flow_mod()
        #msg1.match.nw_dst = IPAddr("10.0.0.2")
        #msg1.match.dl_type = 0x0800
        #msg1.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        #event.connection.send(msg1)
        #log.info("Adhip: 2 flow sent");
        #msg2 = of.ofp_flow_mod()
        #msg2.match.nw_dst = IPAddr("10.0.0.3")
        #msg2.match.dl_type = 0x0800
        #msg2.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        #event.connection.send(msg2)
        #log.info("Adhip: 3 flow sent")
        log.info("Total")

    def _handle_PacketIn (self, event):
        packet = event.parsed
        log.info("Packet came in %s" % packet.type)



def launch ():
    core.registerNew(Fast)

