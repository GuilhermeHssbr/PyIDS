"""
test_rules.py — Testes unitários para o motor de regras
Execute com: pytest tests/
"""

import time
from collections import defaultdict
from scapy.all import IP, TCP, ICMP, ARP, Ether, Raw

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from src.rules import RuleEngine


def make_tcp_packet(src="192.168.1.100", dst="10.0.0.1", dport=80, flags=0x02):
    return IP(src=src, dst=dst) / TCP(dport=dport, flags=flags)


def make_icmp_packet(src="192.168.1.100", dst="10.0.0.1"):
    return IP(src=src, dst=dst) / ICMP()


# ------------------------------------------------------------------ #

class TestPortScan:
    def test_detects_port_scan(self):
        engine = RuleEngine()
        ip_count = defaultdict(int)
        ip_ports = defaultdict(set)
        ip_ts = defaultdict(list)

        src = "192.168.1.50"
        now = time.time()
        ip_ts[src] = [now] * 20  # simula atividade recente

        # Adiciona 20 portas únicas
        for port in range(1, 21):
            ip_ports[src].add(port)

        pkt = make_tcp_packet(src=src, dport=443)
        ip_count[src] = 20

        alerts = engine.check(pkt, ip_count, ip_ports, ip_ts)
        types = [a["type"] for a in alerts]
        assert "PORT SCAN" in types, "Deveria detectar port scan"

    def test_no_false_positive_few_ports(self):
        engine = RuleEngine()
        ip_count = defaultdict(int)
        ip_ports = defaultdict(set)
        ip_ts = defaultdict(list)

        src = "192.168.1.51"
        for port in range(1, 5):   # apenas 4 portas — abaixo do threshold
            ip_ports[src].add(port)

        pkt = make_tcp_packet(src=src)
        alerts = engine.check(pkt, ip_count, ip_ports, ip_ts)
        types = [a["type"] for a in alerts]
        assert "PORT SCAN" not in types


class TestNullScan:
    def test_detects_null_flags(self):
        engine = RuleEngine()
        ip_count = defaultdict(int)
        ip_ports = defaultdict(set)
        ip_ts = defaultdict(list)

        pkt = make_tcp_packet(flags=0x00)
        alerts = engine.check(pkt, ip_count, ip_ports, ip_ts)
        types = [a["type"] for a in alerts]
        assert "NULL SCAN" in types

    def test_normal_syn_not_flagged(self):
        engine = RuleEngine()
        ip_count = defaultdict(int)
        ip_ports = defaultdict(set)
        ip_ts = defaultdict(list)

        pkt = make_tcp_packet(flags=0x02)
        alerts = engine.check(pkt, ip_count, ip_ports, ip_ts)
        types = [a["type"] for a in alerts]
        assert "NULL SCAN" not in types


class TestXmasScan:
    def test_detects_xmas_flags(self):
        engine = RuleEngine()
        ip_count = defaultdict(int)
        ip_ports = defaultdict(set)
        ip_ts = defaultdict(list)

        pkt = make_tcp_packet(flags=0x29)   # FIN+PSH+URG
        alerts = engine.check(pkt, ip_count, ip_ports, ip_ts)
        types = [a["type"] for a in alerts]
        assert "XMAS SCAN" in types


class TestSuspiciousPayload:
    def test_detects_sql_injection(self):
        engine = RuleEngine()
        ip_count = defaultdict(int)
        ip_ports = defaultdict(set)
        ip_ts = defaultdict(list)

        payload = b"GET /search?q=' or 1=1-- HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt = IP(src="1.2.3.4", dst="10.0.0.1") / TCP(dport=80) / Raw(load=payload)

        alerts = engine.check(pkt, ip_count, ip_ports, ip_ts)
        types = [a["type"] for a in alerts]
        assert any("SQL INJECTION" in t for t in types)

    def test_detects_xss(self):
        engine = RuleEngine()
        ip_count = defaultdict(int)
        ip_ports = defaultdict(set)
        ip_ts = defaultdict(list)

        payload = b"POST /comment HTTP/1.1\r\n\r\n<script>alert(1)</script>"
        pkt = IP(src="1.2.3.4", dst="10.0.0.1") / TCP(dport=80) / Raw(load=payload)

        alerts = engine.check(pkt, ip_count, ip_ports, ip_ts)
        types = [a["type"] for a in alerts]
        assert any("XSS" in t for t in types)


class TestArpSpoofing:
    def test_detects_mac_change(self):
        engine = RuleEngine()

        pkt1 = Ether() / ARP(psrc="192.168.0.1", hwsrc="aa:bb:cc:dd:ee:ff")
        pkt2 = Ether() / ARP(psrc="192.168.0.1", hwsrc="11:22:33:44:55:66")

        alerts1 = engine.check_arp(pkt1)
        alerts2 = engine.check_arp(pkt2)

        assert alerts1 == [], "Primeiro ARP não deve gerar alerta"
        types = [a["type"] for a in alerts2]
        assert "ARP SPOOFING" in types

    def test_no_alert_same_mac(self):
        engine = RuleEngine()
        mac = "aa:bb:cc:dd:ee:ff"
        pkt = Ether() / ARP(psrc="10.0.0.1", hwsrc=mac)

        engine.check_arp(pkt)
        alerts = engine.check_arp(pkt)   # mesmo IP, mesmo MAC
        assert alerts == []
