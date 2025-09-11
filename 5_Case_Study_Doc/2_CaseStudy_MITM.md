# Aviation Runway System Cyber Security Case Study 02

### [ MITM Attack On PLC-HMI IEC104 OT Control Channel ]

![](2_CaseStudy_MITM_Img/logo_mid.png)

**Project Design Purpose**: This article will introduce the how we use the [**Mini OT Aviation CAT-II Airport Runway Lights Management Simulation System**](https://www.linkedin.com/pulse/aviation-runway-lights-management-simulation-system-yuancheng-liu-5rzhc) (v_0.2.1) we developed  an attacker can launch and man in the middle attack from an unauthorized IoT  surveillance camera inside the Tower ATC control Room to temporary denied the airport's aircraft traffic control service (landing) and finally cased the airplane fuel low caution situation/accident. This can study designed as part of our IT/OT/IoT workshop and the attack vectors includes: Supply Chain attack, Firmware updates & configuration, IEC61850-104 imperfections, Eavesdropping, Man in the middle, Component Denial of Services.

In this cyber security case study I will cover below sections:

- The attack scenario back ground introduction and some hypothesis we made to create the case study.
- The Aviation Runway Lights Management Simulation System's warning, alert and safety protection system.
- Miss configuration of the runway light control network and how attacker use these weak point/   as the a break point to do the vulnerability exploitation. 
- Detailed attack path and the attack technical details about how the attacker to do the command and control for part of the PLC-HMI IEC104 Control Channel
- Demo of the attack scenario and effect for cyber exercise instance response team to process. 

Important: This case study will introduce and demo the general on the cyber range which is designed for cyber exercise which can flexible inject different vulnerability and misconfiguration.  In real world the safety protection will be much complex and robust,  most the misconfiguration point we introduced are hypothesis  and normally they will be fixed. So it is impossible to do the same attack in the real word system.

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

This cyber attack case study will show the attack use multiple different attack techniques to modified the control data flow channel between the Runway Light and Indicator Control HMI located in the airport runway tower and one of the PLC to control the runway holding light and finally cased deny/delay of the aircraft traffic control service (landing). The Case Study and the demo is implement on a fully digital Aviation Runway Lights Management Simulation System. All the demonstrated attack case/ techniques are only used for education and training for different level of IT-OT cyber security ICS course. 

#### Introduction of the Aviation Cyber Range

The **Mini OT Aviation CAT-II Airport Runway Lights Management Simulation System** is a compact cyber-range platform developed to simulate the **Four** different levels OT environment of a Category II airport precision instrument runway lighting control system as shown in the below system structure diagram:

![](2_CaseStudy_MITM_Img/s_03.png)

It provides the simulation modules from OT-Level 0 physical processes (pure runway device) such as the ALS and ILS light, Airport Surveillance Radar(ASR) system, VHF Comm and Cameras to the OT-Level 3 Operations Management Zone such as Tower control and monitoring HMI System. All the system design follows the FAA ATC "General Standard“. The platform simulate **Four** SCADA systems used for Aircraft Traffic Control: 

- **CAT-II Runway Light System** : The core system simulate 11 types of runway lights and visual indicators.
- **Airport Surveillance Radar System** : The minor assistant system simulate 3 types of radar.
- **Radio Communication System** : The minor assistant system simulated the VHF/UHF pilot-tower and telephone tower-ground communications.
- **Surveillance Camera System** : The landing and take off runway airplane monitor IP camera system.

Currently the cyber range is update to version v_0.2.1 for more introduction, please refer to the v_0.0.1 introduction doc: https://www.linkedin.com/pulse/aviation-runway-lights-management-simulation-system-yuancheng-liu-5rzhc



#### Attack Scenario and Hypothesis 

The real airport IT and OT system are pretty rubust and isolated from against the currently cyber attack, in our case study we did some hypothesis 