"""
rules.py — Motor de regras de detecção de intrusão
"""

import time
from scapy.all import IP, TCP, UDP, ICMP, ARP, Raw

# Limiares configuráveis
PORT_SCAN_THRESHOLD = 15       # portas únicas em janela de tempo
PORT_SCAN_WINDOW = 10          # segundos
FLOOD_THRESHOLD = 200          # pacotes por segundo de um mesmo IP
ARP_SPOOF_TRACK = {}           # rastreia IP → MAC visto


class RuleEngine:
    def __init__(self):
        self.arp_table = {}   # ip → mac legítimo (primeiro visto)

    # ------------------------------------------------------------------ #
    #  Regras para pacotes IP                                              #
    # ------------------------------------------------------------------ #

    def check(self, packet, ip_count, ip_ports, ip_timestamps):
        alerts = []

        if IP not in packet:
            return alerts

        src_ip = packet[IP].src

        # Regra 1 — Port Scan
        alert = self._rule_port_scan(src_ip, ip_ports, ip_timestamps)
        if alert:
            alerts.append(alert)

        # Regra 2 — Flood (DDoS / brute-force volumétrico)
        alert = self._rule_flood(src_ip, ip_timestamps)
        if alert:
            alerts.append(alert)

        # Regra 3 — Null Scan (TCP sem flags)
        if TCP in packet:
            alert = self._rule_null_scan(packet, src_ip)
            if alert:
                alerts.append(alert)

            # Regra 4 — Xmas Scan (FIN+PSH+URG)
            alert = self._rule_xmas_scan(packet, src_ip)
            if alert:
                alerts.append(alert)

            # Regra 5 — SYN Flood
            alert = self._rule_syn_flood(packet, src_ip, ip_timestamps)
            if alert:
                alerts.append(alert)

        # Regra 6 — ICMP Flood / Ping of death
        if ICMP in packet:
            alert = self._rule_icmp_flood(packet, src_ip, ip_timestamps)
            if alert:
                alerts.append(alert)

        # Regra 7 — Payload suspeito (SQLi, XSS, shell)
        if Raw in packet:
            alert = self._rule_suspicious_payload(packet, src_ip)
            if alert:
                alerts.append(alert)

        return alerts

    # ------------------------------------------------------------------ #
    #  Implementações das regras                                           #
    # ------------------------------------------------------------------ #

    def _rule_port_scan(self, src_ip, ip_ports, ip_timestamps):
        now = time.time()
        recent_times = [t for t in ip_timestamps[src_ip] if now - t <= PORT_SCAN_WINDOW]
        unique_ports = len(ip_ports[src_ip])

        if unique_ports >= PORT_SCAN_THRESHOLD and len(recent_times) > 0:
            # Evita alertas duplicados: zera as portas após disparar
            ip_ports[src_ip].clear()
            return {
                "severity": "HIGH",
                "type": "PORT SCAN",
                "src_ip": src_ip,
                "detail": f"{unique_ports} portas únicas em {PORT_SCAN_WINDOW}s",
            }
        return None

    def _rule_flood(self, src_ip, ip_timestamps):
        now = time.time()
        recent = [t for t in ip_timestamps[src_ip] if now - t <= 1.0]
        if len(recent) >= FLOOD_THRESHOLD:
            return {
                "severity": "CRITICAL",
                "type": "PACKET FLOOD",
                "src_ip": src_ip,
                "detail": f"{len(recent)} pacotes/s detectados",
            }
        return None

    def _rule_null_scan(self, packet, src_ip):
        flags = packet[TCP].flags
        if flags == 0:
            return {
                "severity": "MEDIUM",
                "type": "NULL SCAN",
                "src_ip": src_ip,
                "detail": f"TCP sem flags → porta {packet[TCP].dport}",
            }
        return None

    def _rule_xmas_scan(self, packet, src_ip):
        flags = packet[TCP].flags
        # FIN=0x01 PSH=0x08 URG=0x20 → 0x29
        if flags == 0x29:
            return {
                "severity": "MEDIUM",
                "type": "XMAS SCAN",
                "src_ip": src_ip,
                "detail": f"Flags FIN+PSH+URG → porta {packet[TCP].dport}",
            }
        return None

    def _rule_syn_flood(self, packet, src_ip, ip_timestamps):
        # SYN sem ACK em alta frequência
        flags = packet[TCP].flags
        if flags == 0x02:  # somente SYN
            now = time.time()
            syn_times = [t for t in ip_timestamps[src_ip] if now - t <= 2.0]
            if len(syn_times) > 100:
                return {
                    "severity": "CRITICAL",
                    "type": "SYN FLOOD",
                    "src_ip": src_ip,
                    "detail": f"{len(syn_times)} SYNs em 2s → porta {packet[TCP].dport}",
                }
        return None

    def _rule_icmp_flood(self, packet, src_ip, ip_timestamps):
        now = time.time()
        recent = [t for t in ip_timestamps[src_ip] if now - t <= 1.0]
        if len(recent) > 50:
            return {
                "severity": "HIGH",
                "type": "ICMP FLOOD",
                "src_ip": src_ip,
                "detail": f"{len(recent)} pings/s de {src_ip}",
            }
        return None

    def _rule_suspicious_payload(self, packet, src_ip):
        try:
            payload = bytes(packet[Raw]).decode("utf-8", errors="ignore").lower()
        except Exception:
            return None

        signatures = [
            ("sql injection", ["' or 1=1", "union select", "drop table", "-- -"]),
            ("xss", ["<script>", "javascript:", "onerror="]),
            ("shell cmd", ["/bin/sh", "/bin/bash", "cmd.exe", "powershell"]),
            ("path traversal", ["../", "..\\", "%2e%2e"]),
        ]

        for attack_name, patterns in signatures:
            for pat in patterns:
                if pat in payload:
                    return {
                        "severity": "HIGH",
                        "type": f"SUSPICIOUS PAYLOAD ({attack_name.upper()})",
                        "src_ip": src_ip,
                        "detail": f'Padrão detectado: "{pat}"',
                    }
        return None

    # ------------------------------------------------------------------ #
    #  Regras ARP                                                          #
    # ------------------------------------------------------------------ #

    def check_arp(self, packet):
        alerts = []
        if ARP not in packet:
            return alerts

        arp = packet[ARP]
        ip = arp.psrc
        mac = arp.hwsrc

        if ip in self.arp_table:
            if self.arp_table[ip] != mac:
                alerts.append({
                    "severity": "CRITICAL",
                    "type": "ARP SPOOFING",
                    "src_ip": ip,
                    "detail": (
                        f"MAC mudou: {self.arp_table[ip]} → {mac}"
                    ),
                })
        else:
            self.arp_table[ip] = mac

        return alerts
