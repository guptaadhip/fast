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
        msg = of.ofp_flow_mod()
        msg.match.nw_dst = IPAddr("10.0.0.1");
        msg.match.dl_type = 0x800
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)
        log.info("Adhip: 1 flow sent");
        msg1 = of.ofp_flow_mod()
        msg1.match.nw_dst = IPAddr("10.0.0.2");
        msg1.match.dl_type = 0x800
        msg1.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg1)
        log.info("Adhip: 2 flow sent");
        msg2 = of.ofp_flow_mod()
        msg2.match.nw_dst = IPAddr("10.0.0.2");
        msg2.match.dl_type = 0x800
        msg2.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg2)
        log.info("Adhip: 3 flow sent");



def launch ():
    core.registerNew(Fast)

