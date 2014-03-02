from pox.core import core
import pox.openflow.nicira as nx
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp

import time

log = core.getLogger()

class Fast(object):
    
    def __init__ (self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        # Initialize Nicira
        msg = nx.nx_flow_mod()
        event.connection.send(msg)
        
        # Signal Table use 
        msg = nx.nx_flow_mod_table_id()
        event.connection.send(msg)

        #Table 1 -> TCP Table 2 -> ARP
        for temp_table_id in range(1, 5):  
            msg = nx.nx_flow_mod(command=of.OFPFC_DELETE, table_id = temp_table_id)
            event.connection.send(msg)
    
        #Table 0 rule: Selection of tables
        #IP Packet Handling / TCP
        msg = nx.nx_flow_mod()
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.priority = 65000
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 1))
        event.connection.send(msg)
 
        #ARP Packet Handling
        msg = nx.nx_flow_mod()
        msg.priority = 65001
        msg.match.eth_type = pkt.ethernet.ARP_TYPE
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 4))
        event.connection.send(msg)
        log.info("Table 0 done")
      
        #Table 1 Rules
        msg = nx.nx_flow_mod()
        msg.table_id = 1
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.match.tcp_flags = 0x02
        msg.priority = 65001
        #msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 2))
        event.connection.send(msg)
        msg = nx.nx_flow_mod()
        msg.table_id = 1
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.priority = 65000
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        #msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        event.connection.send(msg)
        log.info("Table 1 done")

        #Table 2 Rules 
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.priority = 65000
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        #msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        event.connection.send(msg)


        #Table 2 Rules
        # Set REG0 value to the output port, 0 for controller
        #msg = nx.nx_flow_mod()
        #msg.table_id = 2
        #msg.match.eth_type = pkt.ethernet.IP_TYPE
        #msg.match.ip_dst = "10.0.0.1"
        #msg.priority = 65001
        #msg.actions.append(nx.nx_reg_load(dst=nx.NXM_NX_REG0, value=int(2)))
        #msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        #event.connection.send(msg)

        #msg = nx.nx_flow_mod()
        #msg.table_id = 2
        #msg.match.eth_type = pkt.ethernet.IP_TYPE
        #msg.match.ip_dst = "10.0.0.2"
        #msg.priority = 65001
        #msg.actions.append(nx.nx_reg_load(dst=nx.NXM_NX_REG0, value=int(2)))
        #msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        #event.connection.send(msg)

        #msg = nx.nx_flow_mod()
        #msg.table_id = 2
        #msg.match.eth_type = pkt.ethernet.IP_TYPE
        #msg.match.ip_dst = "10.0.0.3"
        #msg.priority = 65001
        #msg.actions.append(nx.nx_reg_load(dst=nx.NXM_NX_REG0, value=int(3)))
        #msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        #event.connection.send(msg)
       
        #send to controller 
        #msg = nx.nx_flow_mod()
        #msg.table_id = 2
        #msg.priority = 65000
        #msg.actions.append(nx.nx_reg_load(dst=nx.NXM_NX_REG0, value=int(0)))
        #msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        #event.connection.send(msg)
        #log.info("Table 2 done")
        
        #Table 3 Rules
        #for x in range(0,4):
        #    msg = nx.nx_flow_mod()
        #    msg.table_id = 3
        #    msg.match.NXM_NX_REG0 = x
        #    if (x == 0):
        #        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        #    else:
        #        msg.actions.append(of.ofp_action_output(port = x))
        #    event.connection.send(msg)
        #log.info("Table 3 done")

        #Table 4 Rules 
        msg = nx.nx_flow_mod()
        msg.table_id = 4
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)
        log.info("Table 4 done")
        
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

    def _handle_PacketIn (self, event):
        packet = event.parsed
        log.info("Packet came in %s" % packet.type)



def launch ():
    core.registerNew(Fast)

