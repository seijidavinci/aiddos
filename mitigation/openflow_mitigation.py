"""
OpenFlow 1.3 Mitigation Controller Extension
Translates high-level block/unblock decisions into OpenFlow 1.3 FlowMod DROP rules.
"""
import logging
from typing import Optional, Any

logger = logging.getLogger("OpenFlowMitigation")

class OpenFlowMitigationEngine:
    def __init__(self, controller=None, datapath=None):
        self.controller = controller
        self.datapath = datapath

    def set_datapath(self, datapath):
        self.datapath = datapath

    def install_drop_rule(
        self,
        datapath,
        src_ip: str,
        duration: int = 60,
        priority: int = 1000
    ) -> bool:
        """
        Installs an OpenFlow 1.3 FlowMod rule that matches src_ip and applies NO actions (DROP).
        """
        if datapath is None:
            logger.warning(f"No active OpenFlow Datapath. Cannot send FlowMod for {src_ip}.")
            return False

        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # OpenFlow 1.3 match on IPv4 source
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            
            # Empty actions list instructs switch to drop matching packets
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]

            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=duration,
                hard_timeout=duration,
                flags=ofproto.OFPFF_SEND_FLOW_REM
            )
            datapath.send_msg(mod)
            logger.info(f"[OpenFlow 1.3] Installed DROP FlowMod on DPID {datapath.id} for src_ip={src_ip} (timeout={duration}s)")
            return True
        except Exception as e:
            logger.error(f"[OpenFlow 1.3] Failed to install DROP FlowMod for {src_ip}: {e}")
            return False

    def remove_drop_rule(self, datapath, src_ip: str) -> bool:
        """
        Sends an OpenFlow 1.3 FlowMod DELETE command for the blocked src_ip.
        """
        if datapath is None:
            return False
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match
            )
            datapath.send_msg(mod)
            logger.info(f"[OpenFlow 1.3] Removed DROP FlowMod on DPID {datapath.id} for src_ip={src_ip}")
            return True
        except Exception as e:
            logger.error(f"[OpenFlow 1.3] Failed to remove DROP FlowMod for {src_ip}: {e}")
            return False
