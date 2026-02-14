#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════
# setup_attacker.sh — Máquina Atacante (Linux)
# Proyecto : DHCP Starvation Attack
# Autor    : Raelina Ferrera | 2021-2371 | ITLA
# ══════════════════════════════════════════════════════════

set -e

echo "========================================"
echo "  Setup Atacante — DHCP Starvation"
echo "  Raelina Ferrera | 2021-2371 | ITLA"
echo "========================================"

IFACE="eth0"
ATTACKER_IP="10.21.23.50"
GATEWAY="10.21.23.1"

# ── IP estática manual (no pide DHCP para no ser víctima) ──
echo "[*] Configurando IP estática en $IFACE..."
sudo ip addr flush dev $IFACE
sudo ip addr add $ATTACKER_IP/24 dev $IFACE
sudo ip link set $IFACE up
sudo ip route add default via $GATEWAY 2>/dev/null || true

# ── Habilitar IP forwarding ──
echo "[*] Habilitando IP forwarding..."
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# ── Instalar dependencias ──
echo "[*] Instalando dependencias Python..."
pip install scapy colorama --quiet

echo ""
echo "[+] Setup completado."
echo "[*] IP:       $ATTACKER_IP"
echo "[*] Gateway:  $GATEWAY"
echo ""
echo "Ejecutar ataque:"
echo "  sudo python3 scripts/dhcp_starvation.py -i $IFACE -c 204 -d 0.01"