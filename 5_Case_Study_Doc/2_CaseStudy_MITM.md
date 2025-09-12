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

### Attack Scenario and Path Introduction



