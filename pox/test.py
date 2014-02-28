from pox.core import core
import pox.openflow.nicira as nx
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
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
        #ARP Packet Handling
        msg = nx.nx_flow_mod()
        #msg.match.eth_type = int(temp_match_type['dl_type'],5)
        log.info("I got done")
        #msg.match.dl_type = 0x0800
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 1))
        event.connection.send(msg) 
        #ARP Packet Handling
        msg = nx.nx_flow_mod()
        msg.table_id = 1
        #msg.match = nx.match()
        #msg.match.dl_type = 0x0806
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 2))
        event.connection.send(msg)
       
        #Table 1 Rules
        '''msg = nx.nx_flow_mod()
        msg.match = nx.match()
        msg.table_id = 1
        msg.match.nw_dst = IPAddr("10.0.0.1")
        msg.match.dl_type = 0x0800
        msg.actions.append(of.ofp_action_output(port = 1))
        event.connection.send(msg)

        msg = nx.nx_flow_mod()
        msg.match = nx.match()
        msg.table_id = 1
        msg.match.nw_dst = IPAddr("10.0.0.2")
        msg.match.dl_type = 0x0800
        msg.actions.append(of.ofp_action_output(port = 2))
        event.connection.send(msg)

        msg = nx.nx_flow_mod()
        msg.match = nx.match()
        msg.table_id = 1
        msg.match.nw_dst = IPAddr("10.0.0.3")
        msg.match.dl_type = 0x0800
        msg.actions.append(of.ofp_action_output(port = 3))
        event.connection.send(msg)'''

        #Table 2 Rules 
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        #msg.match.dl_type = 0x0806
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)
        
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
        log.info("Packet came in %s")



def launch ():
    core.registerNew(Fast)

