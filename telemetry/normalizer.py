"""
Telemetry Normalizer
Converts diverse flow records (OpenFlow, NetFlow, IPFIX, Socket Sniffer, Replay)
into a unified normalized flow schema for the ML detection engine.
"""
import time
from typing import Dict, Any, Optional

class NormalizedFlow:
    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: int,
        dst_port: int,
        duration_sec: float,
        packet_count: int,
        byte_count: int,
        src_port: int = 0,
        syn_flag_count: int = 0,
        ack_flag_count: int = 0,
        down_up_ratio: float = 0.0,
        telemetry_source: str = "Generic",
        timestamp: Optional[float] = None
    ):
        self.timestamp = timestamp or time.time()
        self.src_ip = str(src_ip)
        self.dst_ip = str(dst_ip)
        self.src_port = int(src_port)
        self.dst_port = int(dst_port)
        self.protocol = int(protocol)
        self.duration_sec = max(float(duration_sec), 0.001)
        self.packet_count = max(int(packet_count), 1)
        self.byte_count = max(int(byte_count), 64)
        
        self.packet_rate = self.packet_count / self.duration_sec
        self.byte_rate = self.byte_count / self.duration_sec
        self.packet_size_mean = self.byte_count / self.packet_count
        self.packet_size_std = 0.0
        self.flow_iat_mean = self.duration_sec / max(self.packet_count - 1, 1)
        self.flow_iat_std = 0.0

        self.syn_flag_count = int(syn_flag_count)
        self.ack_flag_count = int(ack_flag_count)
        self.down_up_ratio = float(down_up_ratio)
        self.telemetry_source = telemetry_source

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration_sec": self.duration_sec,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "packet_rate": self.packet_rate,
            "byte_rate": self.byte_rate,
            "packet_size_mean": self.packet_size_mean,
            "packet_size_std": self.packet_size_std,
            "flow_iat_mean": self.flow_iat_mean,
            "flow_iat_std": self.flow_iat_std,
            "syn_flag_count": self.syn_flag_count,
            "ack_flag_count": self.ack_flag_count,
            "down_up_ratio": self.down_up_ratio,
            "telemetry_source": self.telemetry_source
        }

class TelemetryNormalizer:
    @staticmethod
    def from_openflow(stat_dict: Dict[str, Any]) -> NormalizedFlow:
        return NormalizedFlow(
            src_ip=stat_dict.get("src_ip", "0.0.0.0"),
            dst_ip=stat_dict.get("dst_ip", "0.0.0.0"),
            protocol=stat_dict.get("protocol", 6),
            dst_port=stat_dict.get("dst_port", 80),
            duration_sec=stat_dict.get("duration_sec", 1.0),
            packet_count=stat_dict.get("packet_count", 10),
            byte_count=stat_dict.get("byte_count", 640),
            src_port=stat_dict.get("src_port", 0),
            syn_flag_count=stat_dict.get("syn_flag_count", 0),
            ack_flag_count=stat_dict.get("ack_flag_count", 0),
            down_up_ratio=stat_dict.get("down_up_ratio", 0.0),
            telemetry_source="OpenFlow_1.3"
        )

    @staticmethod
    def from_netflow_v5(record: Dict[str, Any]) -> NormalizedFlow:
        duration = max((record.get("last", 0) - record.get("first", 0)) / 1000.0, 0.001)
        return NormalizedFlow(
            src_ip=record.get("src_ip", "0.0.0.0"),
            dst_ip=record.get("dst_ip", "0.0.0.0"),
            protocol=record.get("prot", 6),
            src_port=record.get("src_port", 0),
            dst_port=record.get("dst_port", 80),
            duration_sec=duration,
            packet_count=record.get("dPkts", 1),
            byte_count=record.get("dOctets", 64),
            syn_flag_count=1 if (record.get("tcp_flags", 0) & 0x02) else 0,
            ack_flag_count=1 if (record.get("tcp_flags", 0) & 0x10) else 0,
            telemetry_source="NetFlow_v5"
        )

    @staticmethod
    def from_ipfix(record: Dict[str, Any]) -> NormalizedFlow:
        return NormalizedFlow(
            src_ip=record.get("sourceIPv4Address", "0.0.0.0"),
            dst_ip=record.get("destinationIPv4Address", "0.0.0.0"),
            protocol=record.get("protocolIdentifier", 6),
            src_port=record.get("sourceTransportPort", 0),
            dst_port=record.get("destinationTransportPort", 80),
            duration_sec=record.get("flowDurationMilliseconds", 1000) / 1000.0,
            packet_count=record.get("packetDeltaCount", 1),
            byte_count=record.get("octetDeltaCount", 64),
            telemetry_source="IPFIX"
        )

    @staticmethod
    def from_socket(record: Dict[str, Any]) -> NormalizedFlow:
        return NormalizedFlow(
            src_ip=record.get("src_ip", "127.0.0.1"),
            dst_ip=record.get("dst_ip", "127.0.0.1"),
            protocol=record.get("protocol", 6),
            src_port=record.get("src_port", 0),
            dst_port=record.get("dst_port", 443),
            duration_sec=record.get("duration_sec", 1.0),
            packet_count=record.get("packet_count", 5),
            byte_count=record.get("byte_count", 500),
            syn_flag_count=record.get("syn_flag_count", 0),
            ack_flag_count=record.get("ack_flag_count", 0),
            down_up_ratio=record.get("down_up_ratio", 0.0),
            telemetry_source="External_Socket"
        )
