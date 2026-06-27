#!/usr/bin/env python3
"""
main.py — Ponto de entrada do PyIDS
Uso: sudo python3 main.py [-i INTERFACE]
"""

import argparse
import sys
import os

def check_root():
    if os.geteuid() != 0:
        print("[ERRO] Execute com sudo — captura de pacotes requer privilégio root.")
        sys.exit(1)

def list_interfaces():
    from scapy.all import get_if_list
    ifaces = get_if_list()
    print("Interfaces disponíveis:")
    for i, iface in enumerate(ifaces, 1):
        print(f"  {i}. {iface}")
    return ifaces

def main():
    check_root()

    parser = argparse.ArgumentParser(
        description="PyIDS — Intrusion Detection System com dashboard no terminal"
    )
    parser.add_argument(
        "-i", "--interface",
        help="Interface de rede a monitorar (ex: eth0, enp0s3). "
             "Se omitido, lista as disponíveis.",
        default=None,
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Lista as interfaces disponíveis e sai.",
    )

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    interface = args.interface
    if interface is None:
        ifaces = list_interfaces()
        print()
        choice = input("Digite o número ou nome da interface: ").strip()
        try:
            idx = int(choice) - 1
            interface = ifaces[idx]
        except (ValueError, IndexError):
            interface = choice  # assumiu nome direto

    print(f"\n[*] Iniciando monitoramento em: {interface}")
    print("[*] Pressione Q no dashboard para encerrar.\n")

    from src.sniffer import NetworkSniffer
    sniffer = NetworkSniffer(interface=interface)
    sniffer.start()


if __name__ == "__main__":
    main()
