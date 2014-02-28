from pox.core import core
import pox.openflow.nicira as nx
import pox.openflow.libopenflow_01 as of
import time

log = core.getLogger()

class Fast(object):
    def __init__ (self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.info("Adhip: I am up");
        #msg = nx.nx_packet_in_format()
        #event.connection.send(msg)
        #log.info("Adhip: I am up 1");
        msg = of.ofp_flow_mod()
        #msg


def launch ():
    core.registerNew(Fast)

