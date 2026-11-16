# Mobile, Hardware, Wireless and ICS

> Tree: `red-team/mobile-hardware-wireless-ics` | **31 sub-skills** | Root router: [`../../SKILL.md`](../../SKILL.md)

**Weak-Model Rule:** Pick the **1 best matching** sub-skill below (`flagship` or `core` first unless a variant profile matches exactly), read its `SKILL.md`, and answer directly using its *Strict Output Contract*.

| Sub-skill | Tier | Focus & When to Use |
|---|---|---|
| [`android-app-security`](android-app-security/SKILL.md) | **core** | Assesses Android applications: manifest and permission review, exported components, storage, deep links and network configuration |
| [`firmware-extraction-and-emulation`](firmware-extraction-and-emulation/SKILL.md) | **core** | Extracts and emulates firmware: image carving, filesystem recovery, architecture identification and full-system emulation for dynamic testing |
| [`hardware-debug-interfaces`](hardware-debug-interfaces/SKILL.md) | **core** | Finds and uses hardware debug interfaces: UART, JTAG, SWD and SPI flash access, pin identification and console recovery |
| [`ics-ot-protocol-attacks`](ics-ot-protocol-attacks/SKILL.md) | **core** | Assesses industrial control protocols: Modbus, DNP3, S7 and OPC UA exposure, unauthenticated control paths and safe testing constraints |
| [`ios-app-security`](ios-app-security/SKILL.md) | **core** | Assesses iOS applications: binary and entitlement review, keychain usage, URL scheme and universal link handling, and storage protections |
| [`iot-device-exploitation`](iot-device-exploitation/SKILL.md) | **core** | Exploits consumer and industrial IoT devices: default and weak credentials, exposed management services, cloud API weaknesses and firmware update |
| [`iot-thread-and-openthread-security`](iot-thread-and-openthread-security/SKILL.md) | **core** | Assesses IEEE 802.15.4 Thread and OpenThread mesh networks: MeshCoP DTLS commissioning (PSKd entropy), Network Key rotation, Border Router IPv6 r |
| [`matter-protocol-commissioning-and-fabric-security`](matter-protocol-commissioning-and-fabric-security/SKILL.md) | **core** | Audits Matter smart-home devices and controllers: PASE/CASE session establishment, Device Attestation Certificate (DAC/PAI/PAA) chain validation, |
| [`mobile-instrumentation-and-pinning-bypass`](mobile-instrumentation-and-pinning-bypass/SKILL.md) | **core** | Instruments mobile apps at runtime and bypasses protections: Frida and Objection usage, SSL pinning defeat, root and jailbreak detection bypass, |
| [`rf-and-sdr-attacks`](rf-and-sdr-attacks/SKILL.md) | **core** | Analyses and attacks radio frequency systems with SDR: signal capture and decoding, replay, jamming considerations and proprietary protocol rever |
| [`wireless-wifi-and-bluetooth-attacks`](wireless-wifi-and-bluetooth-attacks/SKILL.md) | **core** | Attacks wireless networks: WPA and WPA2 handshake capture and cracking, WPS abuse, evil twin and rogue AP, plus Bluetooth and BLE pairing and sni |
| [`android-app-security-component-and-deeplink`](android-app-security-component-and-deeplink/SKILL.md) | **leaf** | Android component and deep link abuse |
| [`android-app-security-static-analysis`](android-app-security-static-analysis/SKILL.md) | **leaf** | Android static analysis |
| [`android-app-security-storage-and-network`](android-app-security-storage-and-network/SKILL.md) | **leaf** | Android storage and network configuration |
| [`automotive-and-can-bus`](automotive-and-can-bus/SKILL.md) | **leaf** | Assesses automotive systems: CAN bus sniffing and injection, diagnostic protocol access, ECU identification and the limits of bench versus vehicl |
| [`gnss-and-satellite-link-security`](gnss-and-satellite-link-security/SKILL.md) | **leaf** | Assesses GNSS receiver resilience (OSNMA/Galileo authentication, C/N0 jump & clock-drift spoofing detection) and satellite/embedded telemetry mod |
| [`hardware-debug-interfaces-jtag-and-swd`](hardware-debug-interfaces-jtag-and-swd/SKILL.md) | **leaf** | JTAG and SWD access |
| [`hardware-debug-interfaces-uart-and-serial`](hardware-debug-interfaces-uart-and-serial/SKILL.md) | **leaf** | UART and serial console access |
| [`ics-ot-protocol-attacks-ot-network-architecture`](ics-ot-protocol-attacks-ot-network-architecture/SKILL.md) | **leaf** | OT network architecture weaknesses |
| [`ics-ot-protocol-attacks-protocol-exposure-assessment`](ics-ot-protocol-attacks-protocol-exposure-assessment/SKILL.md) | **leaf** | ICS protocol exposure assessment |
| [`ieee-802-15-4-and-zigbee-mesh-security`](ieee-802-15-4-and-zigbee-mesh-security/SKILL.md) | **leaf** | Assesses IEEE 802.15.4 and Zigbee networks: well-known Trust Center Link Key (`ZigBeeAlliance09`) fallback during join, unencrypted NWK key trans |
| [`ios-app-security-binary-and-entitlements`](ios-app-security-binary-and-entitlements/SKILL.md) | **leaf** | iOS binary and entitlement analysis |
| [`ios-app-security-storage-and-url-handling`](ios-app-security-storage-and-url-handling/SKILL.md) | **leaf** | iOS storage and URL handling |
| [`mqtt-and-coap-broker-security`](mqtt-and-coap-broker-security/SKILL.md) | **leaf** | Audits IoT messaging brokers (Mosquitto, EMQX, AWS IoT Core, CoAP): anonymous bind, wildcard topic ACL bypass (`#` and `+` subscriptions), `$SYS/ |
| [`physical-security-and-rfid`](physical-security-and-rfid/SKILL.md) | **leaf** | Assesses physical access controls: RFID and NFC cloning, lock bypass, badge cloning and physical entry techniques |
| [`plc-and-scada-exploitation`](plc-and-scada-exploitation/SKILL.md) | **leaf** | Exploits PLC and SCADA components: engineering workstation trust, project file exposure, ladder logic modification and safety considerations |
| [`secure-boot-and-trusted-execution`](secure-boot-and-trusted-execution/SKILL.md) | **leaf** | Analyses secure boot and trusted execution: boot chain verification, key provisioning, TPM and secure element usage, and downgrade paths |
| [`side-channel-and-fault-injection`](side-channel-and-fault-injection/SKILL.md) | **leaf** | Applies side-channel and fault techniques: power and EM analysis, timing attacks and voltage or clock glitching to extract secrets or bypass chec |
| [`wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble`](wireless-wifi-and-bluetooth-attacks-bluetooth-and-ble/SKILL.md) | **leaf** | Bluetooth and BLE attacks |
| [`wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin`](wireless-wifi-and-bluetooth-attacks-rogue-ap-and-evil-twin/SKILL.md) | **leaf** | Rogue AP and evil twin attacks |
| [`wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid`](wireless-wifi-and-bluetooth-attacks-wpa-handshake-and-pmkid/SKILL.md) | **leaf** | WPA handshake and PMKID attacks |
