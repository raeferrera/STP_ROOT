<div align="center">

# 🌳 STP Claim Root Bridge Attack

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-00B050?logo=python)](https://scapy.net)
[![ITLA](https://img.shields.io/badge/ITLA-Cybersecurity-FF6B00)](https://www.itla.edu.do/)
[![IEEE 802.1D](https://img.shields.io/badge/Protocol-IEEE_802.1D-blue)](https://en.wikipedia.org/wiki/Spanning_Tree_Protocol)
[![License](https://img.shields.io/badge/License-Educational-red)](LICENSE)

**Raelina Ferrera · Matrícula: 2021-2371**  
*Seguridad en Redes — Instituto Tecnológico de las Américas*

</div>

---

## 📋 Tabla de Contenidos

- [Objetivo](#objetivo)
- [Conceptos STP](#conceptos-stp)
- [Topología](#topología)
- [Direccionamiento IP](#direccionamiento-ip)
- [Estructura del Repositorio](#estructura-del-repositorio)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Parámetros](#parámetros)
- [Uso](#uso)
- [Cómo Funciona](#cómo-funciona)
- [Capturas de Pantalla](#capturas-de-pantalla)
- [Medidas de Mitigación](#medidas-de-mitigación)
- [Advertencia Legal](#advertencia-legal)

---

## 🎯 Objetivo

El **STP Claim Root Bridge Attack** explota el protocolo Spanning Tree (IEEE 802.1D / 802.1w RSTP) para que el dispositivo atacante sea elegido como **Root Bridge** de la topología de red.

El atacante envía tramas **BPDU de Configuración** con una **prioridad de bridge = 0** (el valor más bajo posible). Dado que STP elige como Root al bridge con menor Bridge ID (prioridad + MAC), todos los switches legítimos reconocen al atacante como el nuevo Root Bridge y recalculan sus puertos, **redirigiendo el tráfico a través del atacante**.

**Impactos del ataque:**
- **MITM a nivel L2:** todo el tráfico inter-switch puede pasar por el atacante.
- **Inestabilidad temporal:** durante la re-convergencia STP puede haber micro-loops y pérdida de paquetes.
- **DoS parcial:** la convergencia STP genera Topology Change Notifications (TCN) que vacían las tablas MAC de todos los switches, causando broadcast storms temporales.

> **Marco de referencia:** MITRE ATT&CK — T1200 (Hardware Additions / L2 Manipulation)

---

## 📚 Conceptos STP

| Término | Descripción |
|---------|-------------|
| **BPDU** | Bridge Protocol Data Unit — mensajes que los switches intercambian para construir la topología STP |
| **Root Bridge** | Switch con el Bridge ID más bajo que actúa como raíz del árbol |
| **Bridge ID** | Compuesto por Prioridad (2B) + MAC (6B). Menor = más preferido |
| **Hello Time** | Intervalo entre BPDUs (default: 2 segundos) |
| **Max Age** | Tiempo antes de descartar información BPDU (default: 20s) |
| **Forward Delay** | Tiempo en estados Listening/Learning antes de Forwarding (default: 15s) |
| **TCN** | Topology Change Notification — señal de cambio en la topología |

**Elección del Root Bridge:**  
`Bridge ID = Priority (4 bits) + System-ID-Extension (12 bits, VLAN) + MAC (48 bits)`  
→ El switch con **menor Bridge ID** gana la elección.  
→ Priority default en Cisco = **32768**. Con el ataque usamos **0**.

---

## 🗺️ Topología

```
        ┌──────────┐
        │  INTERNET│
        │  (Cloud) │
        └────┬─────┘
             │ e0/0 (DHCP)
        ┌────┴─────┐
        │   R1     │
        │  Router  │
        └────┬─────┘
             │ e0/1.23 (10.21.23.1/24)
             │ e0/0
        ┌────┴─────┐
        │   SW1    │  ← Root Bridge LEGÍTIMO (priority 4096)
        │ Priority │     → desplazado por el ataque
        │   4096   │
        └──┬────┬──┘
      e0/2 │    │ e0/1
           │    │
    ┌──────┴──┐ ┌┴──────┐
    │  Linux  │ │  Win  │
    │Atacante │ │Víctima│
    │  ⚡ROOT⚡│ │       │
    └─────────┘ └───────┘
  Priority: 0        DHCP
  MAC:aa:bb:cc...  10.21.23.XX


```
<img width="482" height="365" alt="image" src="https://github.com/user-attachments/assets/48301e90-f48e-4bc8-9dcf-363ab7eec56f" />


**Antes del ataque:** SW1 es Root Bridge (priority 4096).  
**Después del ataque:** Linux (priority 0) es reconocido como Root Bridge.

---

## 📡 Direccionamiento IP

> **Base de matrícula:** 2021-**2371** → VLAN **23**, Subred **10.21.23.0/24**

| Dispositivo | Interfaz   | IP              | STP Priority | Rol            |
|-------------|------------|-----------------|--------------|----------------|
| R1          | e0/0       | DHCP (WAN)      | —            | Router/DHCP    |
| R1          | e0/1.23    | `10.21.23.1/24` | —            | Gateway        |
| SW1         | e0/0       | Trunk → R1      | **4096**     | Root Bridge legítimo |
| SW1         | e0/1       | Access → Win    | —            | —              |
| SW1         | e0/2       | Access → Linux  | —            | —              |
| Linux       | eth0       | `10.21.23.50/24`| **0** ⚠️     | **Atacante (Root falso)** |
| Win         | eth0       | DHCP            | —            | Víctima        |

| Parámetro BPDU (Atacante) | Valor  |
|---------------------------|--------|
| Root Priority             | 0      |
| Bridge Priority           | 0      |
| Root Path Cost            | 0      |
| Hello Time                | 2s     |
| Max Age                   | 20s    |
| Forward Delay             | 15s    |

---

## 📂 Estructura del Repositorio

```
STP_Root/
├── 📜 README.md
├── 📄 requirements.txt
├── 📄 .gitignore
│
├── 📂 scripts/
│   └── 🐍 stp_root.py               # Script principal del ataque STP
│
├── 📂 configs/
│   ├── 📄 R1_config.txt              # Config Router R1
│   ├── 📄 SW1_config.txt             # Config Switch SW1 (Root legítimo)
│   └── 🔧 setup_attacker.sh         # Setup máquina atacante
│
├── 📂 docs/
│   └── 📖 RaelinaFerrera_2021-2371_Informe_P3.pdf
│
└── 📂 evidencias/
    ├── 📂 capturas/                  # Archivos .pcap
    ├── 📂 screenshots/               # Capturas de pantalla
    └── 📂 videos/                    # Video demostración
```

---

## ⚙️ Requisitos

### Hardware / Virtualización

| Componente | Descripción |
|------------|-------------|
| Plataforma | GNS3 o PNETLab |
| Router     | Cisco IOL |
| Switch     | Cisco IOL L2 (**con STP activo**, sin BPDU Guard en el puerto atacante) |
| Atacante   | Linux (Kali / Ubuntu) con Scapy |
| Víctima    | Windows (cualquier versión) |

### Permisos necesarios
El script requiere acceso a bajo nivel a la red (sockets RAW), por lo que es **obligatorio ejecutarlo con `sudo`**.

### Software

| Herramienta | Versión | Propósito |
|-------------|---------|-----------|
| Python      | ≥ 3.8   | Runtime   |
| Scapy       | ≥ 2.5.0 | Construcción y envío de BPDUs |
| Wireshark   | Cualquiera | Captura y análisis de BPDUs |

---

## 🚀 Instalación

```bash
git clone https://github.com/raeferrera/STP_Root.git
cd STP_Root
pip install -r requirements.txt
bash configs/setup_attacker.sh
```

---

## 🔧 Parámetros

| Parámetro         | Largo              | Tipo  | Default | Descripción |
|-------------------|--------------------|-------|---------|-------------|
| `-i`              | `--interface`      | str   | —       | Interfaz de red (**requerido**) |
| `--root-priority` | —                  | int   | `0`     | Prioridad del Root Bridge falso (0 = máximo control) |
| `--bridge-priority`| —                 | int   | `0`     | Prioridad del bridge atacante |
| `--hello`         | —                  | int   | `2`     | Hello Time en segundos |
| `--max-age`       | —                  | int   | `20`    | Max Age en segundos |
| `--fwd-delay`     | —                  | int   | `15`    | Forward Delay en segundos |
| `-c`              | `--count`          | int   | `0` (∞) | Número de BPDUs a enviar |
| `-d`              | `--delay`          | float | `2.0`   | Delay entre BPDUs (simula Hello Time real) |
| `-v`              | `--verbose`        | flag  | off     | Mostrar cada BPDU enviado |

---

## 💻 Uso

### Paso 1: Verificar Root Bridge actual (en SW1)
```
SW1# show spanning-tree vlan 23
```
Deberías ver `SW1` como Root Bridge con priority 4096.

### Paso 2: Lanzar el ataque
```bash
# Ataque continuo con hello time de 2 segundos
sudo python3 scripts/stp_root.py -i eth0

# Ataque verbose (ver cada BPDU)
sudo python3 scripts/stp_root.py -i eth0 -v

# Ataque agresivo (hello time 1s)
sudo python3 scripts/stp_root.py -i eth0 --hello 1 --delay 1.0
```

### Paso 3: Verificar impacto (en SW1)
```
SW1# show spanning-tree vlan 23
```
El atacante (MAC del Linux) debe aparecer como nuevo **Root Bridge**.

### Capturar BPDUs durante el ataque
```bash
sudo tcpdump -i eth0 -w evidencias/capturas/stp_bpdus.pcap ether dst 01:80:c2:00:00:00
```

---

## 🔬 Cómo Funciona

### Formato del BPDU de Configuración (construido por Scapy)

```
Ethernet dst: 01:80:C2:00:00:00 (STP Multicast)
LLC:  DSAP=0x42 SSAP=0x42 Ctrl=0x03
│
└─ BPDU Config (IEEE 802.1D):
   ├── Protocol ID    : 0x0000
   ├── Version        : 0x00 (STP) / 0x02 (RSTP)
   ├── BPDU Type      : 0x00 (Configuration)
   ├── Flags          : 0x00
   ├── Root ID        : 0x0000 + MAC_atacante  ← Priority 0 = ROOT FALSO
   ├── Root Path Cost : 0x00000000
   ├── Bridge ID      : 0x0000 + MAC_atacante
   ├── Port ID        : 0x8001
   ├── Message Age    : 0
   ├── Max Age        : 20s
   ├── Hello Time     : 2s
   └── Forward Delay  : 15s
```

### Proceso de elección

```
Estado ANTES del ataque:
  SW1 Bridge ID = 4096 + MAC_SW1  → Root Bridge
  Linux Bridge ID = (no participa)

Durante el ataque:
  Linux envía BPDU con Root ID = 0 + MAC_Linux
  SW1 compara: 0 < 4096  → ¡El atacante tiene menor ID!
  SW1 actualiza: Root = MAC_Linux
  SW1 envía TCN a todos los switches
  Todos los switches recalculan puertos

Estado DESPUÉS del ataque:
  Linux Bridge ID = 0 + MAC_Linux  → Root Bridge FALSO
  Todo el tráfico fluye a través del atacante
```

---

## 📸 Capturas de Pantalla

> Las capturas se encuentran en `evidencias/screenshots/`

| Evidencia | Descripción |
|-----------|-------------|
| `01_topologia.png` | Topología en GNS3/PNETLab con nombre y matrícula |
| `02_stp_antes.png` | `show spanning-tree vlan 23` — SW1 como Root |
| `03_ataque_ejecutando.png` | Script enviando BPDUs |
| `04_stp_durante.png` | SW1 procesando cambio de Root |
| `05_stp_despues.png` | `show spanning-tree` — atacante como Root Bridge |
| `06_wireshark_bpdus.png` | BPDUs capturados en Wireshark (filtro: `stp`) |
| `07_tcn_generados.png` | Topology Change Notifications en la red |

---

## 🛡️ Medidas de Mitigación

### 1. BPDU Guard (Principal — Cisco IOS)
```
! Habilitar globalmente con portfast
SW1(config)# spanning-tree portfast bpduguard default

! O por puerto específico
SW1(config)# interface Ethernet0/2
SW1(config-if)# spanning-tree bpduguard enable
```
Si se recibe un BPDU en un puerto con BPDU Guard, el puerto pasa a estado **err-disabled** inmediatamente. El ataque queda neutralizado.

### 2. Root Guard
```
! Aplicar en puertos donde nunca debería llegar un Root Bridge
SW1(config)# interface Ethernet0/2
SW1(config-if)# spanning-tree guard root
```
Si se recibe un BPDU superior en un puerto con Root Guard, ese puerto pasa a `root-inconsistent` y no se redirige el tráfico.

### 3. BPDU Filter
```
SW1(config)# interface Ethernet0/2
SW1(config-if)# spanning-tree bpdufilter enable
```
Descarta BPDUs recibidos. Menos recomendado que BPDU Guard porque puede causar loops si se mal configura.

### 4. Establecer Root Bridge fijo
```
SW1(config)# spanning-tree vlan 23 priority 0
! O usar el comando macro
SW1(config)# spanning-tree vlan 23 root primary
```
Asigna la prioridad mínima al switch legítimo para que siempre gane.

| Medida         | Protege contra Root Attack | Efecto si se activa |
|----------------|---------------------------|---------------------|
| BPDU Guard     | ✅ Completo                | Puerto → err-disabled |
| Root Guard     | ✅ Completo                | Puerto → root-inconsistent |
| BPDU Filter    | ⚠️ Parcial                 | Descarta BPDUs (cuidado) |
| Priority fija  | ⚠️ Parcial                 | Reduce riesgo, no lo elimina |

**Recomendación:** Combinar **BPDU Guard** en puertos de acceso + **Root Guard** en puertos trunk + **Root Priority 0** en el switch legítimo.

---

## ⚠️ Advertencia Legal

```
╔══════════════════════════════════════════════════════════════╗
║  USO EXCLUSIVO PARA LABORATORIO EDUCATIVO — ITLA 2021-2371  ║
║                                                              ║
║  ❌ NO usar en redes de producción                          ║
║  ❌ NO usar sin autorización explícita del propietario      ║
║  ✅ Solo en entornos virtuales aislados (GNS3 / PNETLab)    ║
╚══════════════════════════════════════════════════════════════╝
```

---

<div align="center">

**Autor:** Raelina Ferrera  
**Matrícula:** 2021-2371  
**Institución:** Instituto Tecnológico de las Américas (ITLA)  
**Curso:** Seguridad en Redes  
**Fecha:** Febrero 2026

[![GitHub](https://img.shields.io/badge/GitHub-raeferrera-black?logo=github)](https://github.com/raeferrera)
[![ITLA](https://img.shields.io/badge/ITLA-Cybersecurity-orange)](https://www.itla.edu.do/)

</div>
