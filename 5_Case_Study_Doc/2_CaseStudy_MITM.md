# Aviation Runway System Cyber Security Case Study 02

### [ MITM Attack on PLC–HMI IEC104 OT Control Channel ]

![](2_CaseStudy_MITM_Img/logo_mid.png)

The modern airports rely heavily on integrated OT, IT, and IoT systems to ensure safe and efficient runway operations and these systems have also become potential targets for cyberattacks. In this case study, we use our [**Mini OT Aviation CAT-II Airport Runway Lights Management Simulation System**](https://www.linkedin.com/pulse/aviation-runway-lights-management-simulation-system-yuancheng-liu-5rzhc) (v_0.2.1) to demonstrate how a malicious red-team-actor could exploit misconfigurations and weaknesses in the cyber range's PLC-HMI IEC104 control channel through a **Man-in-the-Middle (MITM) attack**. 

This case study is designed as part of our IT/OT/IoT cybersecurity workshop to show six different attack vectors which may happened in the real world system. The scenario assumes an attacker compromises an unauthorized third party IoT surveillance camera inside the Tower ATC Control Room, and from there intercepts and manipulates OT traffic between the HMI and PLCs. The simulated attack results in a temporary denial of runway light control, escalating into an aircraft traffic control service disruption and ultimately creating a Aircraft-fuel-low caution situation.

To guide readers through the exercise, I will cover the following sections:

- Background of the attack scenario and hypotheses used in the case study.
- The warning, alert, and safety protection systems of the Runway Lights Management Simulation System.
- How misconfigurations in the runway light tower network created exploitable weak points.
- Step-by-step attack path with technical details of the MITM control channel manipulation.
- Demonstration of the attack’s impact and its use in training incident response teams.

**Important Note:** This case study takes place in a controlled cyber range environment where vulnerabilities and misconfigurations are deliberately injected for training purposes. In real-world aviation systems, safety protections are more robust and most of the weaknesses described here would be addressed. The attacks demonstrated cannot be directly replicated on operational airport systems.

```python
# Author:      Yuancheng Liu
# Created:     2025/09/10
# Version:     v_0.2.1
# Copyright:   Copyright (c) 2025 Liu Yuancheng
```

**Table of Contents** 

[TOC]

------

### Introduction

This cyberattack case study demonstrates how multiple attack techniques can be combined to manipulate the control data flow channel between the Runway Light and Indicator Control HMI in the airport tower and a PLC responsible for controlling runway holding lights. By exploiting these weaknesses, the attacker is able to cause a **denial or delay of aircraft landing operations**, directly impacting air traffic control services. 

The case study will cover six types of cyber attack vector including:

- Supply chain compromise
- Malicious firmware updates & misconfigurations
- IEC61850-104 protocol imperfections
- Eavesdropping and packet tampering
- Man-in-the-Middle control hijacking
- Component-level denial of service

The entire case study and demonstration are conducted on the latest version of Mini OT Aviation CAT-II Airport Runway Lights Management Simulation System, which specifically designed for research, training, and cyber range exercises. All attack scenarios and techniques presented here are strictly for educational purposes, supporting IT/OT cybersecurity training and ICS-focused courses at different levels.

#### Introduction of the Aviation Cyber Range

The **Mini OT Aviation CAT-II Airport Runway Lights Management Simulation System** is a compact cyber-range platform developed to simulate the **Four** different levels OT environment of a Category II airport precision instrument runway lighting control system as shown in the below system structure diagram:

![](2_CaseStudy_MITM_Img/s_03.png)

It provides the simulation modules from OT-Level 0 physical processes (pure runway device) such as the ALS and ILS light, Airport Surveillance Radar(ASR) system, VHF Comm and Cameras to the OT-Level 3 Operations Management Zone such as Tower control and monitoring HMI System. All the system design follows the FAA ATC "General Standard“. The platform simulate **Four** SCADA systems used for Aircraft Traffic Control: 

- **CAT-II Runway Light System** : The core system simulate 11 types of runway lights and visual indicators.
- **Airport Surveillance Radar System** : The minor assistant system simulate 3 types of radar.
- **Radio Communication System** : The minor assistant system simulated the VHF/UHF pilot-tower and telephone tower-ground communications.
- **Surveillance Camera System** : The landing and take off runway airplane monitor IP camera system.

Currently the cyber range is update to version v_0.2.1 for more introduction, please refer to the v_0.0.1 introduction doc: https://www.linkedin.com/pulse/aviation-runway-lights-management-simulation-system-yuancheng-liu-5rzhc



#### Demo System Environment Configuration

In real-world airports, IT and OT infrastructures are robust, isolated, and designed to resist most currently known cyberattacks. To create a practical training environment for this case study, we deliberately introduced hypothetical weak points and misconfigurations into our cyber range platform. These assumptions allow us to explore how an attacker might exploit vulnerabilities in a less-protected system, without suggesting that such flaws exist in operational airport networks.

The demo network configuration (see figure above) consists of four distinct subnets and a total of 17 virtual machines (VMs) as shown below:

![](2_CaseStudy_MITM_Img/s_04.png)

- **Green Team Subnet** – Represents the physical world connections between devices and PLCs. This subnet is **not directly accessible** to the red team attacker.

- **Blue Team Subnet 1** – Simulates the communication network between the runway tower control room and PLCs. It is protected by IP routing controls and also **not directly accessible** to the attacker.

- **Blue Team Subnet 2** – Represents the **isolated network of the runway control tower**, including SCADA HMIs and monitoring systems. Although attackers cannot connect directly, this subnet may be **indirectly exposed** through maintenance activity or misconfigured devices.

- **Red Team Subnet** – Simulates the attacker’s environment, including C2 infrastructure and compromised third-party IoT devices. Attackers cannot directly bridge into the Blue Team Subnet2 without leveraging an **intermediary path**.

A critical design rule in this simulation is that **no individual has the simultaneous access to both the attacker’s environment and the isolated OT network**. 



#### Case Study Scenario Misconfiguration Hypotheses

Based on the previous environment introduction, we understand there is no way for the red  team attacker to access any part of the OT network in real time. Instead, the attacker must rely on a **careless maintenance engineer** and his compromised laptop to bridge the gap. This creates a realistic insider-like threat vector that highlights the risks of poor endpoint hygiene.

We defined **five key hypotheses** regarding weak points and misconfigurations in this cyber range system:

- **Hypothesis 1** :  A careless maintenance engineer connects his laptop to the internet, giving the attacker an opportunity to install a spy trojan.

- **Hypothesis 2** :  The same laptop is later physically connected to the isolated Level-3 runway OT network for testing, enabling the pre-installed trojan to act inside the control environment.

- **Hypothesis 3** : After leaving the control tower, the maintenance engineer reconnects his laptop to the internet, allowing the attacker to extract sensitive network information and communication samples collected by the trojan.

- **Hypothesis 4** :  The attacker carries out a supply chain compromise, embedding malicious code into the firmware of the IoT camera, which then acts as a stealth access point within the OT environment.
- **Hypothesis 5** : A misconfiguration places a third-party IoT surveillance camera on the same subnet as the runway light control HMI, the maintenance engineer update the camera with the malicious firmware creating an unexpected point of exposure.

These hypotheses, while unrealistic for real-world aviation systems, provide a **controlled, flexible training ground** where we can simulate supply chain compromise, misconfiguration abuse, insider risk, and OT-specific attack paths such as **MITM manipulation of the IEC104 control channel**.



------

### Case Study Attack Scenario and Path

The diagram below illustrates the simulated attack path used in this case study. It shows how an attacker — starting from a compromised maintenance laptop and a tampered IoT camera — establishes a Man-in-the-Middle (MITM) on the **PLC ↔ HMI IEC-104 control channel** to modify the runway holding-light commands data ASDU section, causing a takeoff delay and forcing another inbound aircraft to loiter in the holding pattern until a fuel-low alarm is raised.

![](2_CaseStudy_MITM_Img/s_05.png)

The end-to-end attack unfolds across the following staged timeline (T1 → T13) as marked in the diagram. Each step describes the attacker’s actions, the role of the compromised maintenance engineer as an unwitting insider, and the technical method used to intercept and alter OT traffic.

- **Step-T1 — Initial compromise & beaconing:** The attacker infects the maintenance engineer’s laptop with a spy trojan (via phishing, malvertising, or pre-compromise). The trojan installs network-scanning and packet-capture payload and awaits commands from the attacker’s C2 infrastructure. When the laptop is online, captured telemetry and packets are exfiltrated to C2.
- **Step-T2 — Physical access to OT:** The maintenance engineer, unaware of the infection, disconnects from the internet and takes the laptop into the runway tower room to perform maintenance tasks. He plugs the laptop into a tower RJ45 test port that is connected to the isolated OT environment.
- **Step-T3 — Local reconnaissance inside OT:** While connected, the trojan passively records network traffic between the victim laptop and the Level-1 runway PLC (PLC01), capturing IEC-104 frames, addressing, and sequence patterns used for holding-light control.
- **Step-T4 — Data return & analysis:** After leaving the tower and reconnecting to the internet, the laptop uploads the harvested packet captures to the attacker’s C2. The attacker downloads these captures for offline analysis.
- **Step-T5 — Attack development:** Using the captured traffic and any leaked documentation, the attacker reverse-engineers the IEC-104 messaging, HMI/PLC IPs and control bits. They develop a MITM routine capable of parsing and modifying specific IEC-104 commands and responses. The attacker embeds this MITM payload into a “customized” firmware image for a third-party IoT surveillance camera.
- **Step-T6 — Supply-chain delivery:** The attacker executes a supply-chain or logistics trick to get one camera flashed with the malicious firmware and delivered into the maintenance flow.
- **Step-T7 — Device replacement:** The maintenance engineer (or on-site contractor) replaces a broken camera in the tower with the tampered unit without inspecting its firmware or network placement.
- **Step-T8 — ARP spoofing & traffic redirection:** Once deployed, the malicious camera activates and performs ARP spoofing / local routing manipulation to position itself as a transparent MITM between PLC01 and the HMI, causing traffic to flow PLC01 → Camera → HMI.
- **Step-T9 — Packet parsing & trigger logic:** The camera’s MITM routine parses live IEC-104 frames and waits for a specific command/sequence (the “trigger”) that indicates an operator is issuing a takeoff holding-light change.
- **Step-T10 — Command tampering (takeoff blocked):** When the tower operator presses the HMI button to turn the takeoff holding-light **OFF** (allowing the aircraft to start takeoff), the MITM intercepts and flips the relevant control bit so the command delivered to PLC01 indicates **ON** (hold). The pilot, seeing the physical light, keeps the aircraft at the take off holding area.
- **Step-T11 — State-feedback suppression:** Simultaneously the MITM modifies PLC → HMI state reports so the HMI displays normal/expected PLC states. This conceals the manipulation from the tower operator and prevents operator corrective action.
- **Step-T12 — Cascading operational impact:** An inbound aircraft (Plane-2) on final approach observes the runway as occupied (or receives ATC instruction consistent with runway occupied) and must abort/execute a missed approach, climbing back into the holding pattern.
- **Step-T13 — Safety escalation:** After extended loitering in the holding pattern, the inbound pilot declares a **fuel-low** condition to ATC, prompting priority handling and a safety incident. The tower remains unaware the runway was intentionally withheld due to the MITM manipulation.

This scenario demonstrates how a blended attack — combining endpoint compromise, supply-chain tampering, and an OT-aware MITM — can create dangerous operational outcomes even when primary OT networks are designed to be isolated. All steps above are executed in our cyber range under controlled conditions; they are intended solely to highlight attack mechanics, detection opportunities, and mitigation strategies for training and research.



------

### Cyber Range Warning & Alert System

Before I walk through the demo attack, it’s important to understand the **safety protection mechanisms** built into the cyber range. These mechanisms simulates the real-world Tower ATC safeguards so you can see why the attacker must perform specific reconnaissance and bypass actions to remain covert.

**Purpose & high-level behavior** : The PLCs and HMI in our simulator implement **auto state verification** and a layered **warning/alert generation** system. Whenever an operator issues a control action (e.g., turning on the runway or approach-bar light to release state), the PLCs compare commanded states with the light state sensor feedback. Any mismatch or abnormal condition is flagged and pushed to the tower HMI and to the physical-world simulator display so operators can quickly detect and respond to faults. The PLC light sensor and control logic follow the same logic in this article: https://www.linkedin.com/pulse/use-plc-remote-control-circuit-breaker-power-system-yuancheng-liu-7ljxc, the current version provide 11 types of runway warning, 18 types of runway alert and 4 types of airplane alert.

**How warnings & alerts are visualized**

- The **Physical World Simulator** overlays flashing warning/alert icons directly on the simulated equipment (e.g., a runway light or beacon) so the operator immediately sees the affected component.
- The **HMI** mirrors those notifications in a dedicated **Warning & Alert Indicators panel**, where alarms flash and provide contextual information (type, affected device, timestamp).

![](2_CaseStudy_MITM_Img/s_06.png)

**Detection logic example**:

- Operator press control button → HMI sends IEC-104 control command → PLC actuates device and reads local sensor(s) → PLC reports actual state back to HMI.
- If PLC sensor state ≠ commanded state within a configured timeout or tolerance, the PLC raises an **alert**; if an operator action requires attention but is not critical, a **warning** may be shown instead. The PLC/HMI follow the same sensor/control logic used in our PLC remote-control examples.

**Catalog of alerts & warnings**

- **Runway Warnings (11)** — e.g., Takeoff Holding Light Activated; Beacon Tower power warnings; Runway edge light power off; caution-zone ember lights activated.
- **Runway Alerts (18)** — detailed power/state-mismatch and sensor-failure alerts across approach bars, threshold bars, PAPI, taxiway indicators, radar antenna and VHF antenna.
- **Airplane Alerts (4)** — e.g., Aircraft fuel-low, aircraft emergency climb, radar proximity, runway-light conflict.

These categories provide multi-tiered situational awareness: warnings for operator attention, alerts that generally require immediate incident-response procedures. 

Operational Response

When a **warning** appears the operator is expected to double-check the physical state and proceed with corrective action. When an **alert** occurs the operator must **invoke incident response procedures** (isolate, verify sensors, roll back commands, call maintenance, etc.).

During the cyber attack, the attacker needs to neutralize or evade these protections,  suppress or forge PLC → HMI feedback so the HMI continues to display “normal” despite actual device state changes.



------

### Attack Scenario Demonstration 

This section will introduce the tools, the analysis and the critical steps of the attacker's action of the whole attack scenario steps by steps. 

#### Step-T1~T2 — Initial compromise & beaconing

This demo section covers the attacker’s first two stages: 

- (1) silently implanting a light-weight eavesdropper on the maintenance engineer’s laptop,
- (2) waiting for the engineer to carry that infected endpoint into the isolated OT environment so the implant can capture PLC to victim laptop traffic.

**Toolset used** : The attacker uses a red-team toolkit I developed — **Project Ninja RT Framework** (RTC2 & Trojan-Malware Cyber-Attack Simulation System). Project Ninja provides a C2 console with modular payloads that can be pushed to a target, including a small “light agent” designed for long-duration packet capture and exfiltration. The toolkit workflow is shown in the diagram below.

![](2_CaseStudy_MITM_Img/s_07.png)

For the detail introduction about this attack system, you can check this document: https://www.linkedin.com/pulse/project-ninja-framework-rtc2-trojan-malware-cyber-attack-liu-loihc

**Infection & payload deployment**
From the C2 web trojan control dashboard the attacker enumerates the victim laptop and selects the light agent payload (Function #9 in the console). Using the GUI, the attacker configures the capture parameters:

- target NIC: `ethernet-5` (laptop local RJ45 interface the engineer will later link into the tower test RJ45 port)
- capture duration / interval: `43,200` seconds → **12 hours** (the agent segments captures into several pcap files)
- post-capture behavior: auto-remove the payload module after scheduled recordings finish

![](2_CaseStudy_MITM_Img/s_08.png)

After the payload is installed (Step-T1), the attacker waits for the scheduled maintenance window. On the next workday the maintenance engineer disconnects from the internet, enters the runway tower, and plugs the laptop into the isolated Blue Team Subnet-2 RJ45 test port (Step-T2). During that session the implant captures the HMI ↔ PLC traffic (takeoff/holding light tests and state reports) exactly as planned.

Once deployed, the trojan runs in a low-visibility mode and periodically attempts to beacon to the attacker’s C2 to receive commands and to exfiltrate collected pcaps when the laptop regains internet connectivity.





  





