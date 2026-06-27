"""
sniffer.py — Captura de pacotes de rede em tempo real
"""

import time
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
from src.rules import RuleEngine
from src.alerter import Alerter
from src.dashboard import Dashboard


class NetworkSniffer:
    def __init__(self, interface=None, config=None):
        self.interface = interface
        self.config = config or {}
        self.rule_engine = RuleEngine()
        self.alerter = Alerter()
        self.dashboard = Dashboard(self.alerter)
        self.running = False

        # Estatísticas de tráfego
        self.stats = {
            "packets_total": 0,
            "packets_tcp": 0,
            "packets_udp": 0,
            "packets_icmp": 0,
            "packets_arp": 0,
            "packets_other": 0,
            "bytes_total": 0,
            "alerts_total": 0,
        }

        # Rastreamento de conexões por IP
        self.ip_packet_count = defaultdict(int)
        self.ip_port_set = defaultdict(set)
        self.ip_timestamps = defaultdict(list)

    def process_packet(self, packet):
        """Processa cada pacote capturado."""
        self.stats["packets_total"] += 1
        self.stats["bytes_total"] += len(packet)

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            self.ip_packet_count[src_ip] += 1
            self.ip_timestamps[src_ip].append(time.time())

            # Classifica por protocolo
            if TCP in packet:
                self.stats["packets_tcp"] += 1
                dst_port = packet[TCP].dport
                self.ip_port_set[src_ip].add(dst_port)

            elif UDP in packet:
                self.stats["packets_udp"] += 1
                dst_port = packet[UDP].dport
                self.ip_port_set[src_ip].add(dst_port)

            elif ICMP in packet:
                self.stats["packets_icmp"] += 1

            else:
                self.stats["packets_other"] += 1

            # Verifica regras de detecção
            alerts = self.rule_engine.check(
                packet,
                self.ip_packet_count,
                self.ip_port_set,
                self.ip_timestamps,
            )

            for alert in alerts:
                self.alerter.add_alert(alert)
                self.stats["alerts_total"] += 1

        elif ARP in packet:
            self.stats["packets_arp"] += 1
            alerts = self.rule_engine.check_arp(packet)
            for alert in alerts:
                self.alerter.add_alert(alert)
                self.stats["alerts_total"] += 1

        # Atualiza o dashboard com as últimas estatísticas
        self.dashboard.update_stats(self.stats)

    def start(self):
        """Inicia captura de pacotes e o dashboard."""
        self.running = True

        # Dashboard roda em thread separada
        dash_thread = threading.Thread(target=self.dashboard.run, daemon=True)
        dash_thread.start()

        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        self.dashboard.stop()
