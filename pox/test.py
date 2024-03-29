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
        msg.table_id = 0
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.priority = 65000
        msg.actions.append(nx.nx_multipath(dst = nx.NXM_NX_REG2))
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 1))
        event.connection.send(msg)
 
        #ARP Packet Handling
        msg = nx.nx_flow_mod()
        msg.table_id = 0
        msg.priority = 65001
        msg.match.eth_type = pkt.ethernet.ARP_TYPE
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 4))
        event.connection.send(msg)
        log.info("Table 0 done")
     
        #Table 1 Rules 
        # TBD: State Machine and Hash value
        # New flow function
        msg = nx.nx_flow_mod()
        msg.table_id = 1
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.priority = 65004
        # Signifying New flow
        msg.actions.append(nx.nx_reg_load(dst=nx.NXM_NX_REG0, value=0x0))
        # currently learning based on eth address
        # no hash
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 2))
        event.connection.send(msg)
 
        #Table 2 Rules

        #1. Sync (Should be a Sync)
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.match.NXM_NX_REG0 = 0
        msg.match.tcp_flags = 2
        msg.priority = 65001
        # learn function for table 1
        learn = nx.nx_action_learn(table_id=1,priority=65111)
        learn.spec = [
            nx.flow_mod_spec(src=nx.nx_learn_src_field(nx.NXM_NX_REG2),
                             dst=nx.nx_learn_dst_match(nx.NXM_NX_REG2)),
        ]
        fms = nx.flow_mod_spec.new
        learn.spec.append(fms(load=nx.NXM_NX_REG0, src=nx.nx_learn_src_immediate.u32(None, 1)))
        learn.spec.append(fms(field=nx.NXM_NX_REG0, reserved=True ))
        msg.actions.append(learn)
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        event.connection.send(msg)

        #2. Sync Ack (Should be after sync)
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.match.tcp_flags = 0x12
        msg.priority = 65002
        msg.match.NXM_NX_REG0 = 1
        # learn function for table 1
        learn = nx.nx_action_learn(table_id=1,priority=65111)
        learn.spec = [
            nx.flow_mod_spec(src=nx.nx_learn_src_field(nx.NXM_NX_REG2),
                             dst=nx.nx_learn_dst_match(nx.NXM_NX_REG2)),
        ]
        fms = nx.flow_mod_spec.new
        learn.spec.append(fms(load=nx.NXM_NX_REG0, src=nx.nx_learn_src_immediate.u32(None, 2)))
        learn.spec.append(fms(field=nx.NXM_NX_REG0, reserved=True ))
        msg.actions.append(learn)
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        event.connection.send(msg)

        
        #3. Ack
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.match.tcp_flags = 0x010
        msg.priority = 65003
        msg.match.NXM_NX_REG0 = 2
        # learn function for table 1
        learn = nx.nx_action_learn(table_id=1,priority=65111)
        learn.spec = [
            nx.flow_mod_spec(src=nx.nx_learn_src_field(nx.NXM_NX_REG2),
                             dst=nx.nx_learn_dst_match(nx.NXM_NX_REG2)),
        ]
        fms = nx.flow_mod_spec.new
        learn.spec.append(fms(load=nx.NXM_NX_REG0, src=nx.nx_learn_src_immediate.u32(None, 3)))
        learn.spec.append(fms(field=nx.NXM_NX_REG0, reserved=True ))
        msg.actions.append(learn)
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        event.connection.send(msg)

        #4. Fin
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.match.tcp_flags = 0x010
        msg.priority = 65003
        msg.match.NXM_NX_REG0 = 3
        # learn function for table 1
        learn = nx.nx_action_learn(table_id=1,priority=65111)
        learn.spec = [
            nx.flow_mod_spec(src=nx.nx_learn_src_field(nx.NXM_NX_REG2),
                             dst=nx.nx_learn_dst_match(nx.NXM_NX_REG2)),
        ]
        fms = nx.flow_mod_spec.new
        learn.spec.append(fms(load=nx.NXM_NX_REG0, src=nx.nx_learn_src_immediate.u32(None, 4)))
        learn.spec.append(fms(field=nx.NXM_NX_REG0, reserved=True ))
        msg.actions.append(learn)
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        event.connection.send(msg)


        #5. Fin-Ack
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.match.tcp_flags = 0x010
        msg.priority = 65003
        msg.match.NXM_NX_REG0 = 4
        # learn function for table 1
        learn = nx.nx_action_learn(table_id=1,priority=65111)
        learn.spec = [
            nx.flow_mod_spec(src=nx.nx_learn_src_field(nx.NXM_NX_REG2),
                             dst=nx.nx_learn_dst_match(nx.NXM_NX_REG2)),
        ]
        fms = nx.flow_mod_spec.new
        learn.spec.append(fms(load=nx.NXM_NX_REG0, src=nx.nx_learn_src_immediate.u32(None, 5)))
        learn.spec.append(fms(field=nx.NXM_NX_REG0, reserved=True ))
        msg.actions.append(learn)
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        event.connection.send(msg)

        #7. Ack
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.match.tcp_flags = 0x010
        msg.priority = 65003
        msg.match.NXM_NX_REG0 = 5
        # learn function for table 1
        learn = nx.nx_action_learn(table_id=1,priority=65111)
        learn.spec = [
            nx.flow_mod_spec(src=nx.nx_learn_src_field(nx.NXM_NX_REG2),
                             dst=nx.nx_learn_dst_match(nx.NXM_NX_REG2)),
        ]
        fms = nx.flow_mod_spec.new
        learn.spec.append(fms(load=nx.NXM_NX_REG0, src=nx.nx_learn_src_immediate.u32(None, 6)))
        learn.spec.append(fms(field=nx.NXM_NX_REG0, reserved=True ))
        msg.actions.append(learn)
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        event.connection.send(msg)

        #8. RST
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.match.tcp_flags = 0x14
        msg.priority = 65003
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        event.connection.send(msg)

        #9. PSH-Ack
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.match.tcp_flags = 0x18
        msg.priority = 65003
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        event.connection.send(msg)

        #9. Ack
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_proto = ipv4.TCP_PROTOCOL
        msg.match.tcp_flags = 0x10
        msg.priority = 65003
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        event.connection.send(msg)

        #send to controller  currently sending to the destination as no old state stored
        msg = nx.nx_flow_mod()
        msg.table_id = 2
        msg.priority = 64999
        msg.actions.append(nx.nx_reg_load(dst=nx.NXM_NX_REG1, value=int(1)))
        msg.actions.append(nx.nx_action_resubmit.resubmit_table(table = 3))
        event.connection.send(msg)
        log.info("Table 2 done")


        #Table 3 Rules: Forward the packet to the Destination
        msg = nx.nx_flow_mod()
        msg.table_id = 3
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_dst = "10.0.0.1"
        msg.priority = 65001
        msg.actions.append(of.ofp_action_output(port = 1))
        event.connection.send(msg)

        msg = nx.nx_flow_mod()
        msg.table_id = 3
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_dst = "10.0.0.2"
        msg.priority = 65001
        msg.actions.append(of.ofp_action_output(port = 2))
        event.connection.send(msg)

        msg = nx.nx_flow_mod()
        msg.table_id = 3
        msg.match.eth_type = pkt.ethernet.IP_TYPE
        msg.match.ip_dst = "10.0.0.3"
        msg.priority = 65001
        msg.actions.append(of.ofp_action_output(port = 3))
        event.connection.send(msg)
       
        #send to controller 
        msg = nx.nx_flow_mod()
        msg.table_id = 3
        msg.match.NXM_NX_REG1 = 1 
        msg.priority = 65005
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        event.connection.send(msg)
        log.info("Table 3 done")
        
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
        tcpp = event.parsed.find('tcp')
        if tcpp and tcpp.SYN:
            log.info("Packet SYN")
        if tcpp and tcpp.ACK:
            log.info("Packet ACK")
        if tcpp and tcpp.PSH:
            log.info("Packet PSH")
        if tcpp and tcpp.RST:
            log.info("Packet RST")
        if tcpp and tcpp.URG:
            log.info("Packet URG")
        if tcpp and tcpp.FIN:
            log.info("Packet FIN")
            



def launch ():
    core.registerNew(Fast)