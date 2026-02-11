# Awesome Honeypots [![Awesome Honeypots](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome) ⭐ 436,589 | 🐛 68 | 📅 2026-01-28 with stars

A curated list of awesome honeypots, plus related components and much more, divided into categories such as Web, services, and others, with a focus on free and open source projects.

There is no pre-established order of items in each category, the order is for contribution. If you want to contribute, please read the [guide](origin/CONTRIBUTING.md).

Discover more awesome lists at [sindresorhus/awesome](https://github.com/sindresorhus/awesome) ⭐ 436,589 | 🐛 68 | 📅 2026-01-28.

# Contents

* [Awesome Honeypots ](#awesome-honeypots-)
* [Contents](#contents)
  * [Related Lists](#related-lists)
  * [Honeypots](#honeypots)
  * [Honeyd Tools](#honeyd-tools)
  * [Network and Artifact Analysis](#network-and-artifact-analysis)
  * [Data Tools](#data-tools)
  * [Guides](#guides)

## Related Lists

* [awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis) ⭐ 13,426 | 🐛 24 | 📅 2024-06-07 - Some overlap here for artifact analysis.
* [awesome-pcaptools](https://github.com/caesar0301/awesome-pcaptools) ⭐ 3,355 | 🐛 10 | 📅 2025-09-03 - Useful in network traffic analysis.

## Honeypots

* Low interaction honeypot

  * [T-Pot](https://github.com/dtag-dev-sec/tpotce) ⭐ 8,744 | 🐛 2 | 🌐 C | 📅 2026-01-29 - All in one honeypot appliance from telecom provider T-Mobile
  * [beelzebub](https://github.com/mariocandela/beelzebub) ⭐ 1,836 | 🐛 6 | 🌐 Go | 📅 2026-02-10 - A secure honeypot framework, extremely easy to configure by yaml 🚀
  * [Honeyperl](https://sourceforge.net/projects/honeyperl/) - Honeypot software based in Perl with plugins developed for many functions like : wingates, telnet, squid, smtp, etc.

* SSH Honeypots

  * [endlessh](https://github.com/skeeto/endlessh) ⭐ 8,406 | 🐛 48 | 🌐 C | 📅 2024-06-03 - SSH tarpit that slowly sends an endless banner. ([docker image](https://hub.docker.com/r/linuxserver/endlessh))
  * [Cowrie](https://github.com/cowrie/cowrie) ⭐ 6,163 | 🐛 45 | 🌐 Python | 📅 2026-02-11 - Cowrie SSH Honeypot (based on kippo).
  * [Kippo](https://github.com/desaster/kippo) ⭐ 1,713 | 🐛 83 | 🌐 Python | 📅 2023-11-19 - Medium interaction SSH honeypot.
  * [sshesame](https://github.com/jaksi/sshesame) ⭐ 1,709 | 🐛 17 | 🌐 Go | 📅 2024-10-21 - Fake SSH server that lets everyone in and logs their activity.
  * [ssh-honeypot](https://github.com/droberson/ssh-honeypot) ⭐ 671 | 🐛 11 | 🌐 C | 📅 2024-10-29 - Fake sshd that logs IP addresses, usernames, and passwords.
  * [HonSSH](https://github.com/tnich/honssh) ⚠️ Archived - Logs all SSH communications between a client and server.
  * [sshhipot](https://github.com/magisterquis/sshhipot) ⭐ 172 | 🐛 5 | 🌐 Go | 📅 2018-05-13 - High-interaction MitM SSH honeypot.
  * [MockSSH](https://github.com/ncouture/MockSSH) ⭐ 129 | 🐛 9 | 🌐 Python | 📅 2025-05-20 - Mock an SSH server and define all commands it supports (Python, Twisted).
  * [sshsyrup](https://github.com/mkishere/sshsyrup) ⭐ 99 | 🐛 6 | 🌐 Go | 📅 2019-02-25 - Simple SSH Honeypot with features to capture terminal activity and upload to asciinema.org.
  * [twisted-honeypots](https://github.com/lanjelot/twisted-honeypots) ⭐ 87 | 🐛 3 | 🌐 Shell | 📅 2019-12-27 - SSH, FTP and Telnet honeypots based on Twisted.
  * [Kojoney2](https://github.com/madirish/kojoney2) ⭐ 39 | 🐛 3 | 🌐 Ruby | 📅 2015-01-06 - Low interaction SSH honeypot written in Python and based on Kojoney by Jose Antonio Coret.
  * [hnypots-agent)](https://github.com/joshrendek/hnypots-agent) ⭐ 39 | 🐛 1 | 🌐 PureBasic | 📅 2024-12-08 - SSH Server in Go that logs username and password combinations.
  * [sshForShits](https://github.com/traetox/sshForShits) ⭐ 39 | 🐛 1 | 🌐 Go | 📅 2020-04-08 - Framework for a high interaction SSH honeypot.
  * [go0r](https://github.com/fzerorubigd/go0r) ⭐ 37 | 🐛 0 | 🌐 Go | 📅 2015-04-07 - Simple ssh honeypot in Golang.
  * [go-sshoney](https://github.com/ashmckenzie/go-sshoney) ⚠️ Archived - SSH Honeypot.
  * [honeypot.go](https://github.com/mdp/honeypot.go) ⭐ 30 | 🐛 0 | 🌐 Go | 📅 2013-12-20 - SSH Honeypot written in Go.
  * [ssh-honeypot](https://github.com/amv42/sshd-honeypot) ⭐ 27 | 🐛 0 | 🌐 C | 📅 2018-12-20 - Modified version of the OpenSSH deamon that forwards commands to Cowrie where all commands are interpreted and returned.
  * [ssh-auth-logger](https://github.com/JustinAzoff/ssh-auth-logger) ⭐ 25 | 🐛 0 | 🌐 Go | 📅 2026-02-04 - Low/zero interaction SSH authentication logging honeypot.
  * [Blacknet](https://github.com/morian/blacknet) ⭐ 24 | 🐛 0 | 🌐 Python | 📅 2024-03-21 - Multi-head SSH honeypot system.
  * [hornet](https://github.com/czardoz/hornet) ⭐ 24 | 🐛 3 | 🌐 Python | 📅 2018-04-30 - Medium interaction SSH honeypot that supports multiple virtual hosts.
  * [Longitudinal Analysis of SSH Cowrie Honeypot Logs](https://github.com/deroux/longitudinal-analysis-cowrie) ⭐ 19 | 🐛 0 | 🌐 HTML | 📅 2022-11-14 - Python based command line tool to analyze cowrie logs over time.
  * [ssh-honeypotd](https://github.com/sjinks/ssh-honeypotd) ⭐ 19 | 🐛 2 | 🌐 C | 📅 2026-02-05 - Low-interaction SSH honeypot written in C.
  * [DShield docker](https://github.com/xme/dshield-docker) ⭐ 17 | 🐛 3 | 🌐 Shell | 📅 2016-06-08 - Docker container running cowrie with DShield output enabled.
  * [sshlowpot](https://github.com/magisterquis/sshlowpot) ⚠️ Archived - Yet another no-frills low-interaction SSH honeypot in Go.
  * [honeyssh](https://github.com/ppacher/honeyssh) ⭐ 14 | 🐛 0 | 🌐 Go | 📅 2019-10-18 - Credential dumping SSH honeypot with statistics.
  * [gohoney](https://github.com/PaulMaddox/gohoney) ⭐ 13 | 🐛 1 | 🌐 Go | 📅 2013-12-12 - SSH honeypot written in Go.
  * [Kippo\_JunOS](https://github.com/gregcmartin/Kippo_JunOS) ⭐ 11 | 🐛 0 | 🌐 Python | 📅 2015-12-22 - Kippo configured to be a backdoored netscreen.
  * [Malbait](https://github.com/batchmcnulty/Malbait) ⭐ 9 | 🐛 1 | 🌐 Perl | 📅 2024-04-27 - Simple TCP/UDP honeypot implemented in Perl.
  * [HUDINX](https://github.com/Cryptix720/HUDINX) ⭐ 8 | 🐛 1 | 🌐 Tcl | 📅 2019-04-30 - Tiny interaction SSH honeypot engineered in Python to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker.
  * [cowrie2neo](https://github.com/xlfe/cowrie2neo) ⭐ 8 | 🐛 0 | 🌐 Python | 📅 2017-10-16 - Parse cowrie honeypot logs into a neo4j database.
  * [hived](https://github.com/sahilm/hived) ⭐ 4 | 🐛 0 | 🌐 Go | 📅 2017-08-28 - Golang-based honeypot.
  * [Kojoney](http://kojoney.sourceforge.net/) - Python-based Low interaction honeypot that emulates an SSH server implemented with Twisted Conch.
  * [LongTail Log Analysis @ Marist College](http://longtail.it.marist.edu/honey/) - Analyzed SSH honeypot logs.

* Mobile Analysis Tool

  * [Androguard](https://github.com/androguard/androguard) ⭐ 5,950 | 🐛 44 | 🌐 Python | 📅 2026-01-12 - Reverse engineering, Malware and goodware analysis of Android applications and more.
  * [APKinspector](https://github.com/honeynet/apkinspector/) ⭐ 854 | 🐛 15 | 🌐 Java | 📅 2013-02-25 - Powerful GUI tool for analysts to analyze the Android applications.

* Other/random

  * [OpenCanary](https://github.com/thinkst/opencanary) ⭐ 2,767 | 🐛 9 | 🌐 Python | 📅 2026-02-11 - Modular and decentralised honeypot daemon that runs several canary versions of services that alerts when a service is (ab)used.
  * [miniprint](https://github.com/sa7mon/miniprint) ⭐ 203 | 🐛 18 | 🌐 Python | 📅 2023-07-09 - A medium interaction printer honeypot.
  * [Masscanned](https://github.com/ivre/masscanned) ⭐ 137 | 🐛 9 | 🌐 Rust | 📅 2026-02-04 - Let's be scanned. A low-interaction honeypot focused on network scanners and bots. It integrates very well with IVRE to build a self-hosted alternative to GreyNoise.
  * [CitrixHoneypot](https://github.com/MalwareTech/CitrixHoneypot) ⭐ 118 | 🐛 2 | 🌐 HTML | 📅 2020-01-15 - Detect and log CVE-2019-19781 scan and exploitation attempts.
  * [Log4Pot](https://github.com/thomaspatzke/Log4Pot) ⭐ 93 | 🐛 0 | 🌐 Python | 📅 2024-11-29 - A honeypot for the Log4Shell vulnerability (CVE-2021-44228).
  * [NOVA](https://github.com/DataSoft/Nova) ⭐ 81 | 🐛 6 | 🌐 C++ | 📅 2023-06-08 - Uses honeypots as detectors, looks like a complete system.
  * [ciscoasa\_honeypot](https://github.com/cymmetria/ciscoasa_honeypot) ⭐ 57 | 🐛 5 | 🌐 JavaScript | 📅 2018-11-23 A low interaction honeypot for the Cisco ASA component capable of detecting CVE-2018-0101, a DoS and remote code execution vulnerability.
  * [dicompot](https://github.com/nsmfoo/dicompot) ⭐ 27 | 🐛 2 | 🌐 Go | 📅 2025-12-05 - DICOM Honeypot.
  * [medpot](https://github.com/schmalle/medpot) ⭐ 26 | 🐛 4 | 🌐 Go | 📅 2024-05-20 -  HL7 / FHIR honeypot.
  * [OpenFlow Honeypot (OFPot)](https://github.com/upa/ofpot) ⭐ 24 | 🐛 0 | 🌐 Python | 📅 2013-01-05 - Redirects traffic for unused IPs to a honeypot, built on POX.
  * [Damn Simple Honeypot (DSHP)](https://github.com/naorlivne/dshp) ⭐ 19 | 🐛 0 | 🌐 Python | 📅 2016-05-31 - Honeypot framework with pluggable handlers.
  * [IPP Honey](https://gitlab.com/bontchev/ipphoney) - A honeypot for the Internet Printing Protocol.

* System instrumentation

  * [Fibratus](https://github.com/rabbitstack/fibratus) ⭐ 2,428 | 🐛 63 | 🌐 Go | 📅 2026-02-10 - Tool for exploration and tracing of the Windows kernel.
  * [Sysdig](https://sysdig.com/opensource/) - Open source, system-level exploration allows one to capture system state and activity from a running GNU/Linux instance, then save, filter, and analyze the results.

* Honeytokens
  * [CanaryTokens](https://github.com/thinkst/canarytokens) ⭐ 2,016 | 🐛 14 | 🌐 HTML | 📅 2026-02-09 - Self-hostable honeytoken generator and reporting dashboard; demo version available at [CanaryTokens.org](https://canarytokens.org/generate).
  * [Honeyλ (HoneyLambda)](https://github.com/0x4D31/honeylambda) ⭐ 522 | 🐛 1 | 🌐 Python | 📅 2018-10-20 - Simple, serverless application designed to create and monitor URL honeytokens, on top of AWS Lambda and Amazon API Gateway.
  * [dcept](https://github.com/secureworks/dcept) ⭐ 509 | 🐛 4 | 🌐 Python | 📅 2022-07-13 - Tool for deploying and detecting use of Active Directory honeytokens.
  * [Honeybits](https://github.com/0x4D31/honeybits) ⚠️ Archived - Simple tool designed to enhance the effectiveness of your traps by spreading breadcrumbs and honeytokens across your production servers and workstations to lure the attacker toward your honeypots.
  * [honeyku](https://github.com/0x4D31/honeyku) ⚠️ Archived - Heroku-based web honeypot that can be used to create and monitor fake HTTP endpoints (i.e. honeytokens).

* Service Honeypots
  * [pyrdp](https://github.com/gosecure/pyrdp) ⭐ 1,753 | 🐛 63 | 🌐 Python | 📅 2025-07-27 - RDP man-in-the-middle and library for Python 3 with the ability to watch connections live or after the fact.
  * [RDPy](https://github.com/citronneur/rdpy) ⭐ 1,734 | 🐛 78 | 🌐 Python | 📅 2021-06-28 - Microsoft Remote Desktop Protocol (RDP) honeypot implemented in Python.
  * [honeytrap](https://github.com/honeytrap/honeytrap) ⭐ 1,304 | 🐛 148 | 🌐 Go | 📅 2023-10-09 - Advanced Honeypot framework written in Go that can be connected with other honeypot software.
  * [honeypots](https://github.com/qeeqbox/honeypots) ⭐ 941 | 🐛 13 | 🌐 Python | 📅 2025-12-03 - 25 different honeypots in a single pypi package! (dns, ftp, httpproxy, http, https, imap, mysql, pop3, postgres, redis, smb, smtp, socks5, ssh, telnet, vnc, mssql, elastic, ldap, ntp, memcache, snmp, oracle, sip and irc).
  * [dionaea](https://github.com/DinoTools/dionaea) ⭐ 788 | 🐛 65 | 🌐 Python | 📅 2024-08-01 - Home of the dionaea honeypot.
  * [HoneyPy](https://github.com/foospidy/HoneyPy) ⚠️ Archived - Low interaction honeypot.
  * [ADBHoney](https://github.com/huuck/ADBHoney) ⭐ 179 | 🐛 3 | 🌐 Python | 📅 2025-03-05 - Low interaction honeypot that simulates an Android device running Android Debug Bridge (ADB) server process.
  * [Trapster Commmunity](https://github.com/0xBallpoint/trapster-community) ⭐ 157 | 🐛 1 | 🌐 Python | 📅 2025-12-02 - Modural and easy to install Python Honeypot, with comprehensive alerting
  * [rdppot](https://github.com/kryptoslogic/rdppot) ⭐ 69 | 🐛 0 | 🌐 Python | 📅 2019-06-06 - RDP honeypot
  * [Ensnare](https://github.com/ahoernecke/ensnare) ⭐ 68 | 🐛 3 | 🌐 Ruby | 📅 2017-04-18 - Easy to deploy Ruby honeypot.
  * [ddospot](https://github.com/aelth/ddospot) ⭐ 63 | 🐛 3 | 🌐 Python | 📅 2020-12-27 - NTP, DNS, SSDP, Chargen and generic UDP-based amplification DDoS honeypot.
  * [honeyntp](https://github.com/fygrave/honeyntp) ⭐ 55 | 🐛 1 | 🌐 Python | 📅 2014-03-27 - NTP logger/honeypot.
  * [honeypot-camera](https://github.com/alexbredo/honeypot-camera) ⭐ 53 | 🐛 1 | 🌐 Python | 📅 2015-06-18 - Observation camera honeypot.
  * [SMB Honeypot](https://github.com/r0hi7/HoneySMB) ⭐ 50 | 🐛 5 | 🌐 Python | 📅 2021-03-28 - High interaction SMB service honeypot capable of capturing wannacry-like Malware.
  * [Honeyport](https://github.com/securitygeneration/Honeyport) ⭐ 47 | 🐛 0 | 🌐 Shell | 📅 2017-02-22 - Simple honeyport written in Bash and Python.
  * [troje](https://github.com/dutchcoders/troje/) ⭐ 45 | 🐛 0 | 🌐 Go | 📅 2014-08-12 - Honeypot that runs each connection with the service within a separate LXC container.
  * [Helix](https://github.com/Zeerg/helix-honeypot) ⚠️ Archived - K8s API Honeypot with Active Defense Capabilities.
  * [dhp](https://github.com/ciscocsirt/dhp) ⭐ 33 | 🐛 1 | 🌐 Python | 📅 2020-10-06 - Simple Docker Honeypot server emulating small snippets of the Docker HTTP API.
  * [honeypot-ftp](https://github.com/alexbredo/honeypot-ftp) ⭐ 33 | 🐛 5 | 🌐 Python | 📅 2024-01-22 - FTP Honeypot.
  * [WebLogic honeypot](https://github.com/Cymmetria/weblogic_honeypot) ⭐ 33 | 🐛 3 | 🌐 Python | 📅 2020-04-25 - Low interaction honeypot to detect CVE-2017-10271 in the Oracle WebLogic Server component of Oracle Fusion Middleware.
  * [honeycomb\_plugins](https://github.com/Cymmetria/honeycomb_plugins) ⭐ 27 | 🐛 47 | 🌐 HTML | 📅 2023-10-19 - Plugin repository for Honeycomb, the honeypot framework by Cymmetria.
  * [Tom's Honeypot](https://github.com/inguardians/toms_honeypot) ⭐ 27 | 🐛 0 | 🌐 Python | 📅 2015-04-27 - Low interaction Python honeypot.
  * [Honeyprint](https://github.com/glaslos/honeyprint) ⭐ 21 | 🐛 0 | 🌐 Python | 📅 2016-01-28 - Printer honeypot.
  * [Honeygrove](https://github.com/UHH-ISS/honeygrove) ⭐ 20 | 🐛 7 | 🌐 HTML | 📅 2021-06-07 - Multi-purpose modular honeypot based on Twisted.
  * [MICROS honeypot](https://github.com/Cymmetria/micros_honeypot) ⭐ 17 | 🐛 2 | 🌐 ASP | 📅 2018-09-25 - Low interaction honeypot to detect CVE-2018-2636 in the Oracle Hospitality Simphony component of Oracle Hospitality Applications (MICROS).
  * [node-ftp-honeypot](https://github.com/christophe77/node-ftp-honeypot) ⭐ 6 | 🐛 0 | 🌐 JavaScript | 📅 2023-10-05 - FTP server honeypot in JS.
  * [WhiteFace Honeypot](https://github.com/csirtgadgets/csirtg-honeypot) ⭐ 6 | 🐛 0 | 🌐 Python | 📅 2015-04-24 - Twisted based honeypot for WhiteFace.
  * [DolosHoneypot](https://github.com/Marist-Innovation-Lab/DolosHoneypot) ⭐ 4 | 🐛 0 | 🌐 CSS | 📅 2018-04-23 - SDN (software defined networking) honeypot.
  * [AMTHoneypot](https://github.com/packetflare/amthoneypot) - Honeypot for Intel's AMT Firmware Vulnerability CVE-2017-5689.
  * [GenAIPot](https://github.com/ls1911/GenAIPot) - The first A.I based open source honeypot. supports POP3 and SMTP protocols and generates content using A.I based on user description.
  * \[honeydb] (<https://honeydb.io/downloads>) - Multi-service honeypot that is easy to deploy and configure. Can be configured to send interaction data to to HoneyDB's centralized collectors for access via REST API.
  * [Lyrebird](https://hub.docker.com/r/lyrebird/honeypot-base/) - Modern high-interaction honeypot framework.

* Server

  * [fapro](https://github.com/fofapro/fapro) ⭐ 1,609 | 🐛 14 | 🌐 Python | 📅 2025-01-02 - Fake Protocol Server.
  * [Heralding](https://github.com/johnnykv/heralding) ⭐ 388 | 🐛 19 | 🌐 Python | 📅 2024-05-21 - Credentials catching honeypot.
  * [Artillery](https://github.com/trustedsec/artillery/) ⭐ 336 | 🐛 8 | 📅 2020-09-30 - Open-source blue team tool designed to protect Linux and Windows operating systems through multiple methods.
  * [telnet-iot-honeypot](https://github.com/Phype/telnet-iot-honeypot) ⭐ 313 | 🐛 3 | 🌐 Python | 📅 2024-02-02 - Python telnet honeypot for catching botnet binaries.
  * [glutton](https://github.com/mushorg/glutton) ⭐ 294 | 🐛 27 | 🌐 Go | 📅 2025-12-31 - All eating honeypot.
  * [telnetlogger](https://github.com/robertdavidgraham/telnetlogger) ⭐ 244 | 🐛 6 | 🌐 C | 📅 2017-03-05 - Telnet honeypot designed to track the Mirai botnet.
  * [Hontel](https://github.com/stamparm/hontel) ⭐ 163 | 🐛 0 | 🌐 Python | 📅 2019-03-05 - Telnet Honeypot.
  * [MTPot](https://github.com/Cymmetria/MTPot) ⭐ 106 | 🐛 0 | 🌐 Python | 📅 2017-03-20 - Open Source Telnet Honeypot, focused on Mirai malware.
  * [honeytrap](https://github.com/tillmannw/honeytrap) ⭐ 95 | 🐛 5 | 🌐 C | 📅 2017-06-04 - Low-interaction honeypot and network security tool written to catch attacks against TCP and UDP services.
  * [UDPot Honeypot](https://github.com/jekil/UDPot) ⭐ 51 | 🐛 0 | 🌐 Python | 📅 2026-01-23 - Simple UDP/DNS honeypot scripts.
  * [go-HoneyPot](https://github.com/Mojachieee/go-HoneyPot) ⭐ 48 | 🐛 0 | 🌐 Go | 📅 2019-10-05 - Honeypot server written in Go.
  * [portlurker](https://github.com/bartnv/portlurker) ⭐ 36 | 🐛 1 | 🌐 Rust | 📅 2026-02-04 - Port listener in Rust with protocol guessing and safe string display.
  * [honeymail](https://github.com/sec51/honeymail) ⭐ 33 | 🐛 3 | 🌐 Go | 📅 2016-08-09 - SMTP honeypot written in Golang.
  * [potd](https://github.com/lnslbrty/potd) ⚠️ Archived - Highly scalable low- to medium-interaction SSH/TCP honeypot designed for OpenWrt/IoT devices leveraging several Linux kernel features, such as namespaces, seccomp and thread capabilities.
  * [imap-honey](https://github.com/yvesago/imap-honey) ⭐ 26 | 🐛 0 | 🌐 Go | 📅 2022-04-22 - IMAP honeypot written in Golang.
  * [HoneyWRT](https://github.com/CanadianJeff/honeywrt) ⭐ 25 | 🐛 2 | 🌐 Python | 📅 2015-08-25 - Low interaction Python honeypot designed to mimic services or ports that might get targeted by attackers.
  * [vnclowpot](https://github.com/magisterquis/vnclowpot) ⚠️ Archived - Low interaction VNC honeypot.
  * [slipm-honeypot](https://github.com/rshipp/slipm-honeypot) ⭐ 19 | 🐛 0 | 🌐 Shell | 📅 2020-06-14 - Simple low-interaction port monitoring honeypot.
  * [SIREN](https://github.com/blaverick62/SIREN) ⭐ 15 | 🐛 0 | 🌐 Python | 📅 2018-03-17 - Semi-Intelligent HoneyPot Network - HoneyNet Intelligent Virtual Environment.
  * [Honeyd](https://github.com/provos/honeyd) ⭐ 13 | 🐛 0 | 🌐 C | 📅 2015-03-14 - See [honeyd tools](#honeyd-tools).
  * [go-emulators](https://github.com/kingtuna/go-emulators) ⭐ 11 | 🐛 0 | 🌐 Go | 📅 2016-02-28 - Honeypot Golang emulators.
  * [Yet Another Fake Honeypot (YAFH)](https://github.com/fnzv/YAFH) ⭐ 10 | 🐛 0 | 🌐 Go | 📅 2017-12-08 - Simple honeypot written in Go.
  * [Bifrozt](https://github.com/Ziemeck/bifrozt-ansible) ⭐ 6 | 🐛 0 | 🌐 Shell | 📅 2016-03-17 - Automatic deploy bifrozt with ansible.
  * [arctic-swallow](https://github.com/ajackal/arctic-swallow) ⭐ 3 | 🐛 0 | 🌐 Python | 📅 2018-07-26 - Low interaction honeypot.
  * [TelnetHoney](https://github.com/balte/TelnetHoney) ⭐ 2 | 🐛 0 | 🌐 C# | 📅 2016-01-20 - Simple telnet honeypot.
  * [Amun](http://amunhoney.sourceforge.net) - Vulnerability emulation honeypot.
  * [Bait and Switch](http://baitnswitch.sourceforge.net) - Redirects all hostile traffic to a honeypot that is partially mirroring your production system.
  * [Conpot](http://conpot.org/) - Low interactive server side Industrial Control Systems honeypot.
  * [Honeysink](http://www.honeynet.org/node/773) - Open source network sinkhole that provides a mechanism for detection and prevention of malicious traffic on a given network.
  * [KFSensor](http://www.keyfocus.net/kfsensor/) - Windows based honeypot Intrusion Detection System (IDS).
  * [LaBrea](http://labrea.sourceforge.net/labrea-info.html) - Takes over unused IP addresses, and creates virtual servers that are attractive to worms, hackers, and other denizens of the Internet.
  * [mwcollectd](https://www.openhub.net/p/mwcollectd) - Versatile malware collection daemon, uniting the best features of nepenthes and honeytrap.

* ICS/SCADA honeypots

  * [Conpot](https://github.com/mushorg/conpot) ⭐ 1,426 | 🐛 115 | 🌐 Python | 📅 2024-12-24 - ICS/SCADA honeypot.
  * [GasPot](https://github.com/sjhilt/GasPot) ⭐ 145 | 🐛 0 | 🌐 Python | 📅 2024-04-30 - Veeder Root Gaurdian AST, common in the oil and gas industry.
  * [gridpot](https://github.com/sk4ld/gridpot) ⭐ 60 | 🐛 3 | 🌐 C | 📅 2015-03-23 - Open source tools for realistic-behaving electric grid honeynets.
  * [SCADA honeynet](http://scadahoneynet.sourceforge.net) - Building Honeypots for Industrial Networks.
  * [scada-honeynet](http://www.digitalbond.com/blog/2007/07/24/scada-honeynet-article-in-infragard-publication/) - Mimics many of the services from a popular PLC and better helps SCADA researchers understand potential risks of exposed control system devices.

* PDF document inspector

  * [peepdf](https://github.com/jesparza/peepdf) ⭐ 1,425 | 🐛 49 | 🌐 Python | 📅 2024-08-19 - Powerful Python tool to analyze PDF documents.

* Web honeypots

  * [HellPot](https://github.com/yunginnanet/HellPot) ⭐ 1,096 | 🐛 12 | 🌐 Go | 📅 2025-12-19 - Honeypot that tries to crash the bots and clients that visit it's location.
  * [django-admin-honeypot](https://github.com/dmpayton/django-admin-honeypot) ⭐ 1,076 | 🐛 20 | 🌐 Python | 📅 2024-04-10 - Fake Django admin login screen to notify admins of attempted unauthorized access.
  * [galah](https://github.com/0x4D31/galah) ⭐ 634 | 🐛 5 | 🌐 Go | 📅 2025-07-24 - an LLM-powered web honeypot using the OpenAI API.
  * [Glastopf](https://github.com/mushorg/glastopf) ⭐ 596 | 🐛 1 | 🌐 Python | 📅 2024-07-23 - Web Application Honeypot.
  * Snare/Tanner - successors to Glastopf
    * [Snare](https://github.com/mushorg/snare) ⭐ 476 | 🐛 28 | 🌐 Python | 📅 2024-06-10 - Super Next generation Advanced Reactive honeypot.
    * [Tanner](https://github.com/mushorg/tanner) ⭐ 231 | 🐛 29 | 🌐 Python | 📅 2024-08-19 - Evaluating SNARE events.
  * [Python-Honeypot](https://github.com/OWASP/Python-Honeypot) ⭐ 475 | 🐛 26 | 🌐 Python | 📅 2024-09-15 - OWASP Honeypot, Automated Deception Framework.
  * [Laravel Application Honeypot](https://github.com/msurguy/Honeypot) ⭐ 438 | 🐛 10 | 🌐 PHP | 📅 2025-02-20 - Simple spam prevention package for Laravel applications.
  * WordPress honeypots
    * [wordpot](https://github.com/gbrindisi/wordpot) ⭐ 185 | 🐛 4 | 🌐 CSS | 📅 2023-02-07 - WordPress Honeypot.
    * [HonnyPotter](https://github.com/MartinIngesen/HonnyPotter) ⭐ 35 | 🐛 1 | 🌐 PHP | 📅 2018-01-18 - WordPress login honeypot for collection and analysis of failed login attempts.
    * [wp-smart-honeypot](https://github.com/freak3dot/wp-smart-honeypot) ⭐ 29 | 🐛 5 | 🌐 PHP | 📅 2017-10-13 - WordPress plugin to reduce comment spam with a smarter honeypot.
    * [HoneyPress](https://github.com/kungfuguapo/HoneyPress) ⭐ 8 | 🐛 1 | 🌐 PHP | 📅 2020-11-19 - Python based WordPress honeypot in a Docker container.
  * [Cloud Active Defense](https://github.com/SAP/cloud-active-defense?tab=readme-ov-file) ⭐ 103 | 🐛 23 | 🌐 JavaScript | 📅 2026-02-10 - Cloud active defense lets you deploy decoys right into your cloud applications, putting adversaries into a dilemma: to hack or not to hack?
  * [StrutsHoneypot](https://github.com/Cymmetria/StrutsHoneypot) ⭐ 72 | 🐛 0 | 🌐 PHP | 📅 2017-03-24 - Struts Apache 2 based honeypot as well as a detection module for Apache 2 servers.
  * [owa-honeypot](https://github.com/joda32/owa-honeypot) ⭐ 69 | 🐛 2 | 🌐 HTML | 📅 2023-05-02 - A basic flask based Outlook Web Honey pot.
  * [WebTrap](https://github.com/IllusiveNetworks-Labs/WebTrap) ⭐ 68 | 🐛 2 | 🌐 Python | 📅 2018-03-28 - Designed to create deceptive webpages to deceive and redirect attackers away from real websites.
  * [phpmyadmin\_honeypot](https://github.com/gfoss/phpmyadmin_honeypot) ⭐ 68 | 🐛 3 | 🌐 PHP | 📅 2018-02-11 - Simple and effective phpMyAdmin honeypot.
  * [modpot](https://github.com/referefref/modpot) ⭐ 63 | 🐛 0 | 🌐 HTML | 📅 2024-05-08 - Modpot is a modular web application honeypot framework and management application written in Golang and making use of gin framework.
  * [drupo](https://github.com/d1str0/drupot) ⭐ 58 | 🐛 0 | 🌐 HTML | 📅 2019-07-14 - Drupal Honeypot.
  * [basic-auth-pot (bap)](https://github.com/bjeborn/basic-auth-pot) ⭐ 53 | 🐛 0 | 🌐 Python | 📅 2015-01-15 - HTTP Basic Authentication honeypot.
  * [honeyhttpd](https://github.com/bocajspear1/honeyhttpd) ⭐ 53 | 🐛 7 | 🌐 Python | 📅 2024-06-29 - Python-based web server honeypot builder.
  * [Nodepot](https://github.com/schmalle/Nodepot) ⭐ 47 | 🐛 1 | 🌐 HTML | 📅 2015-08-23 - NodeJS web application honeypot.
  * [EoHoneypotBundle](https://github.com/eymengunay/EoHoneypotBundle) ⭐ 37 | 🐛 7 | 🌐 PHP | 📅 2025-06-13 - Honeypot type for Symfony2 forms.
  * [bwpot](https://github.com/graneed/bwpot) ⭐ 28 | 🐛 0 | 🌐 Shell | 📅 2019-03-10 - Breakable Web applications honeyPot.
  * [honeyup](https://github.com/LogoiLab/honeyup) ⭐ 28 | 🐛 0 | 🌐 Rust | 📅 2025-04-19 - An uploader honeypot designed to look like poor website security.
  * [Lophiid](https://github.com/mrheinen/lophiid/) ⭐ 25 | 🐛 21 | 🌐 Go | 📅 2026-02-08 - Distributed web application honeypot to interact with large scale exploitation attempts.
  * [stack-honeypot](https://github.com/CHH/stack-honeypot) ⭐ 24 | 🐛 0 | 🌐 PHP | 📅 2014-01-30 - Inserts a trap for spam bots into responses.
  * [Express honeypot](https://github.com/christophe77/express-honeypot) ⭐ 21 | 🐛 0 | 🌐 JavaScript | 📅 2025-02-26 - RFI & LFI honeypot using nodeJS and express.
  * [smart-honeypot](https://github.com/freak3dot/smart-honeypot) ⭐ 18 | 🐛 0 | 🌐 PHP | 📅 2014-04-19 - PHP Script demonstrating a smart honey pot.
  * [Servletpot](https://github.com/schmalle/servletpot) ⭐ 15 | 🐛 0 | 🌐 Java | 📅 2013-05-12 - Web application Honeypot.
  * [tomcat-manager-honeypot](https://github.com/helospark/tomcat-manager-honeypot) ⭐ 12 | 🐛 0 | 🌐 Java | 📅 2017-08-27 - Honeypot that mimics Tomcat manager endpoints. Logs requests and saves attacker's WAR file for later study.
  * [PasitheaHoneypot](https://github.com/Marist-Innovation-Lab/PasitheaHoneypot) ⭐ 4 | 🐛 0 | 🌐 Java | 📅 2018-04-24 - RestAPI honeypot.
  * [Google Hack Honeypot](http://ghh.sourceforge.net) - Designed to provide reconnaissance against attackers that use search engines as a hacking tool against your resources.
  * [Shadow Daemon](https://shadowd.zecure.org/overview/introduction/) - Modular Web Application Firewall / High-Interaction Honeypot for PHP, Perl, and Python apps.
  * [shockpot](https://github.com/threatstream/shockpot) - WebApp Honeypot for detecting Shell Shock exploit attempts.

* Dockerized Low Interaction packaging

  * [Dockerized Thug](https://hub.docker.com/r/honeynet/thug/) - Dockerized [Thug](https://github.com/buffer/thug) ⭐ 1,020 | 🐛 3 | 🌐 Python | 📅 2026-01-13 to analyze malicious web content.
  * [Dockerpot](https://github.com/mrschyte/dockerpot) ⭐ 151 | 🐛 0 | 🌐 Shell | 📅 2015-05-05 - Docker based honeypot.
  * [mhn-core-docker](https://github.com/MattCarothers/mhn-core-docker) ⭐ 35 | 🐛 1 | 🌐 Dockerfile | 📅 2022-03-28 - Core elements of the Modern Honey Network implemented in Docker.
  * [Manuka](https://github.com/andrewmichaelsmith/manuka) ⭐ 26 | 🐛 2 | 🌐 Shell | 📅 2015-03-21 - Docker based honeypot (Dionaea and Kippo).
  * [Docker honeynet](https://github.com/sreinhardt/Docker-Honeynet) ⭐ 22 | 🐛 0 | 🌐 Shell | 📅 2014-12-21 - Several Honeynet tools set up for Docker containers.
  * [honey\_ports](https://github.com/run41/honey_ports) ⭐ 9 | 🐛 0 | 🌐 Shell | 📅 2019-10-26 - Very simple but effective docker deployed honeypot to detect port scanning in your environment.

* VM monitoring and tools

  * [Antivmdetect](https://github.com/nsmfoo/antivmdetection) ⭐ 769 | 🐛 11 | 🌐 Python | 📅 2022-11-05 - Script to create templates to use with VirtualBox to make VM detection harder.
  * [VMCloak](https://github.com/hatching/vmcloak) ⭐ 518 | 🐛 66 | 🌐 Python | 📅 2024-05-14 - Automated Virtual Machine Generation and Cloaking for Cuckoo Sandbox.
  * [vmitools](http://libvmi.com/) - C library with Python bindings that makes it easy to monitor the low-level details of a running virtual machine.

* Spamtrap

  * [Mailoney](https://github.com/phin3has/mailoney) ⭐ 281 | 🐛 2 | 🌐 Python | 📅 2025-12-30 - SMTP honeypot written in python.
  * [Shiva](https://github.com/shiva-spampot/shiva) ⭐ 140 | 🐛 9 | 🌐 Python | 📅 2025-03-31 - Spam Honeypot with Intelligent Virtual Analyzer.
    * [Shiva The Spam Honeypot Tips And Tricks For Getting It Up And Running](https://www.pentestpartners.com/security-blog/shiva-the-spam-honeypot-tips-and-tricks-for-getting-it-up-and-running/)
  * [SpamHAT](https://github.com/miguelraulb/spamhat) ⭐ 27 | 🐛 2 | 🌐 Perl | 📅 2016-06-01 - Spam Honeypot Tool.
  * [SendMeSpamIDS.py](https://github.com/johestephan/VerySimpleHoneypot) ⚠️ Archived - Simple SMTP fetch all IDS and analyzer.
  * [SMTPLLMPot](https://github.com/referefref/SMTPLLMPot) ⭐ 7 | 🐛 0 | 🌐 Shell | 📅 2023-12-01 - A super simple SMTP Honeypot built using GPT3.5
  * [honeypot](https://github.com/jadb/honeypot) ⭐ 2 | 🐛 0 | 🌐 PHP | 📅 2016-01-23 - The Project Honey Pot un-official PHP SDK.
  * [Mail::SMTP::Honeypot](https://metacpan.org/pod/release/MIKER/Mail-SMTP-Honeypot-0.11/Honeypot.pm) - Perl module that appears to provide the functionality of a standard SMTP server.
  * [Spamhole](http://www.spamhole.net/)
  * [spamd](http://man.openbsd.org/cgi-bin/man.cgi?query=spamd%26apropos=0%26sektion=0%26manpath=OpenBSD+Current%26arch=i386%26format=html)

* Server (Bluetooth)

  * [Bluepot](https://github.com/andrewmichaelsmith/bluepot) ⭐ 265 | 🐛 4 | 🌐 Java | 📅 2021-01-02

* Data Collection / Data Sharing

  * [HPFeeds](https://github.com/rep/hpfeeds/) ⭐ 218 | 🐛 6 | 🌐 Python | 📅 2023-10-19 - Lightweight authenticated publish-subscribe protocol.
  * [HPfriends](http://hpfriends.honeycloud.net/#/home) - Honeypot data-sharing platform.
    * [hpfriends - real-time social data-sharing](https://heipei.io/sigint-hpfriends/) - Presentation about HPFriends feed system

* SIP

  * [SentryPeer](https://github.com/SentryPeer/SentryPeer) ⭐ 205 | 🐛 1 | 🌐 C | 📅 2026-02-10 - Protect your SIP Servers from bad actors.

* Botnet C2 tools

  * [Hale](https://github.com/pjlantz/Hale) ⭐ 203 | 🐛 2 | 🌐 Python | 📅 2022-05-23 - Botnet command and control monitor.
  * [dnsMole](https://code.google.com/archive/p/dns-mole/) - Analyses DNS traffic and potentionaly detect botnet command and control server activity, along with infected hosts.

* Database Honeypots

  * [Elastic honey](https://github.com/jordan-wright/elastichoney) ⭐ 190 | 🐛 6 | 🌐 Go | 📅 2015-07-14 - Simple Elasticsearch Honeypot.
  * [NoSQLpot](https://github.com/torque59/nosqlpot) ⭐ 103 | 🐛 5 | 🌐 Python | 📅 2023-10-17 - Honeypot framework built on a NoSQL-style database.
  * [MongoDB-HoneyProxy](https://github.com/Plazmaz/MongoDB-HoneyProxy) ⭐ 93 | 🐛 1 | 🌐 JavaScript | 📅 2023-02-20 - MongoDB honeypot proxy.
  * [mysql-honeypotd](https://github.com/sjinks/mysql-honeypotd) ⭐ 36 | 🐛 2 | 🌐 C | 📅 2026-02-05 - Low interaction MySQL honeypot written in C.
  * [ESPot](https://github.com/mycert/ESPot) ⭐ 28 | 🐛 0 | 🌐 JavaScript | 📅 2014-08-25 - Elasticsearch honeypot written in NodeJS, to capture every attempts to exploit CVE-2014-3120.
  * [Delilah](https://github.com/SecurityTW/delilah) ⭐ 25 | 🐛 0 | 🌐 Python | 📅 2015-06-11 - Elasticsearch Honeypot written in Python (originally from Novetta).
  * [RedisHoneyPot](https://github.com/cypwnpwnsocute/RedisHoneyPot) ⭐ 25 | 🐛 0 | 🌐 Go | 📅 2021-04-23 - High Interaction Honeypot Solution for Redis protocol.
  * [MysqlPot](https://github.com/schmalle/MysqlPot) ⭐ 22 | 🐛 0 | 🌐 C# | 📅 2012-10-14 - MySQL honeypot, still very early stage.
  * [pghoney](https://github.com/betheroot/pghoney) ⭐ 20 | 🐛 3 | 🌐 Go | 📅 2024-05-20 - Low-interaction Postgres Honeypot.
  * [sticky\_elephant](https://github.com/betheroot/sticky_elephant) ⭐ 12 | 🐛 0 | 🌐 Ruby | 📅 2024-08-06 - Medium interaction postgresql honeypot.
  * [ElasticPot](https://gitlab.com/bontchev/elasticpot) - An Elasticsearch Honeypot.

* Client

  * [Jsunpack-n](https://github.com/urule99/jsunpack-n) ⭐ 168 | 🐛 30 | 🌐 Python | 📅 2015-04-02
  * [YALIH (Yet Another Low Interaction Honeyclient)](https://github.com/Masood-M/yalih) ⭐ 68 | 🐛 1 | 🌐 Python | 📅 2019-06-18 - Low-interaction client honeypot designed to detect malicious websites through signature, anomaly, and pattern matching techniques.
  * [HoneySpider Network](https://github.com/CERT-Polska/hsn2-bundle) ⚠️ Archived - Highly-scalable system integrating multiple client honeypots to detect malicious websites.
  * [PhoneyC](https://github.com/honeynet/phoneyc) ⭐ 26 | 🐛 0 | 🌐 C | 📅 2015-05-22 - Python honeyclient (later replaced by Thug).
  * [Capture-HPC-NG](https://github.com/CERT-Polska/HSN-Capture-HPC-NG) ⚠️ Archived
  * [CWSandbox / GFI Sandbox](https://www.gfi.com/products-and-solutions/all-products)
  * [Capture-HPC-Linux](https://redmine.honeynet.org/projects/linux-capture-hpc/wiki)
  * [Capture-HPC](https://projects.honeynet.org/capture-hpc) - High interaction client honeypot (also called honeyclient).
  * [HoneyBOT](http://www.atomicsoftwaresolutions.com/)
  * [HoneyC](https://projects.honeynet.org/honeyc)
  * [HoneyWeb](https://code.google.com/archive/p/gsoc-honeyweb/) - Web interface created to manage and remotely share Honeyclients resources.
  * [MonkeySpider](http://monkeyspider.sourceforge.net)
  * [Pwnypot](https://github.com/shjalayeri/pwnypot) - High Interaction Client Honeypot.
  * [Rumal](https://github.com/thugs-rumal/) - Thug's Rumāl: a Thug's dress and weapon.
  * [Shelia](https://www.cs.vu.nl/~herbertb/misc/shelia/) - Client-side honeypot for attack detection.
  * [Thug](https://buffer.github.io/thug/) - Python-based low-interaction honeyclient.
  * [Thug Distributed Task Queuing](https://thug-distributed.readthedocs.io/en/latest/index.html)
  * [Trigona](https://www.honeynet.org/project/Trigona)
  * [URLQuery](https://urlquery.net/)

* Binary debugger

  * [Hexgolems - Schem Debugger Frontend](https://github.com/hexgolems/schem) ⭐ 141 | 🐛 21 | 🌐 HTML | 📅 2015-11-11 - Debugger frontend.
  * [Hexgolems - Pint Debugger Backend](https://github.com/hexgolems/pint) ⭐ 33 | 🐛 9 | 🌐 C++ | 📅 2013-11-06 - Debugger backend and LUA wrapper for PIN.

* IOT Honeypot

  * [HoneyThing](https://github.com/omererdem/honeything) ⭐ 129 | 🐛 4 | 🌐 Python | 📅 2016-03-16 - TR-069 Honeypot.
  * [Kako](https://github.com/darkarnium/kako) ⚠️ Archived - Honeypots for a number of well known and deployed embedded device vulnerabilities.

* Anti-honeypot stuff

  * [honeydet](https://github.com/referefref/honeydet) ⭐ 108 | 🐛 0 | 🌐 Go | 📅 2025-03-22 - Signature based honeypot detector tool written in Golang
  * [kippo\_detect](https://github.com/andrew-morris/kippo_detect) ⭐ 59 | 🐛 0 | 🌐 Python | 📅 2014-12-10 - Offensive component that detects the presence of the kippo honeypot.
  * [canarytokendetector](https://github.com/referefref/canarytokendetector) ⭐ 25 | 🐛 0 | 🌐 Shell | 📅 2023-12-09 - Tool for detection and nullification of Thinkst CanaryTokens

* Honeypot for USB-spreading malware

  * [Ghost-usb](https://github.com/honeynet/ghost-usb-honeypot) ⭐ 102 | 🐛 3 | 🌐 C | 📅 2015-03-24 - Honeypot for malware that propagates via USB storage devices.

* Distributed Honeypots

  * [DemonHunter](https://github.com/RevengeComing/DemonHunter) ⭐ 63 | 🐛 1 | 🌐 Python | 📅 2018-04-29 - Low interaction honeypot server.

* IPv6 attack detection tool

  * [ipv6-attack-detector](https://github.com/mzweilin/ipv6-attack-detector/) ⭐ 43 | 🐛 0 | 🌐 Python | 📅 2020-07-30 - Google Summer of Code 2012 project, supported by The Honeynet Project organization.

* Passive network audit framework parser

  * [Passive Network Audit Framework (pnaf)](https://github.com/jusafing/pnaf) ⭐ 32 | 🐛 0 | 🌐 Perl | 📅 2018-05-17 - Framework that combines multiple passive and automated analysis techniques in order to provide a security assessment of network platforms.

* Low interaction honeypot (router back door)

  * [WAPot](https://github.com/lcashdol/WAPot) ⭐ 20 | 🐛 0 | 🌐 CSS | 📅 2018-11-14 - Honeypot that can be used to observe traffic directed at home routers.
  * [Honeypot-32764](https://github.com/knalli/honeypot-for-tcp-32764) ⚠️ Archived - Honeypot for router backdoor (TCP 32764).

* Honeypot

  * [IMHoneypot](https://github.com/mushorg/imhoneypot) ⭐ 16 | 🐛 1 | 🌐 Python | 📅 2016-03-22
  * [Deception Toolkit](http://www.all.net/dtk/dtk.html)

* Honeypot deployment

  * [honeyfs](https://github.com/referefref/honeyfs) ⭐ 9 | 🐛 1 | 🌐 Shell | 📅 2023-12-05 - Tool to create artificial file systems for medium/high interaction honeypots.
  * [Modern Honeynet Network](http://threatstream.github.io/mhn/) - Streamlines deployment and management of secure honeypots.

* Dynamic code instrumentation toolkit

  * [Frida](https://www.frida.re) - Inject JavaScript to explore native apps on Windows, Mac, Linux, iOS and Android.

* Tool to convert website to server honeypots

  * [HIHAT](http://hihat.sourceforge.net/) - Transform arbitrary PHP applications into web-based high-interaction Honeypots.

* Malware collector

  * [Kippo-Malware](https://bruteforcelab.com/kippo-malware) - Python script that will download all malicious files stored as URLs in a Kippo SSH honeypot database.

* Distributed sensor deployment

  * [Community Honey Network](https://communityhoneynetwork.readthedocs.io/en/stable/) - CHN aims to make deployments honeypots and honeypot management tools easy and flexible. The default deployment method uses Docker Compose and Docker to deploy with a few simple commands.
  * [Modern Honey Network](https://github.com/threatstream/mhn) - Multi-snort and honeypot sensor management, uses a network of VMs, small footprint SNORT installations, stealthy dionaeas, and a centralized server for management.

* Network Analysis Tool

  * [Tracexploit](https://code.google.com/archive/p/tracexploit/) - Replay network packets.

* Log anonymizer

  * [LogAnon](http://code.google.com/archive/p/loganon/) - Log anonymization library that helps having anonymous logs consistent between logs and network captures.

* honeynet farm traffic redirector

  * [Honeymole](https://web.archive.org/web/20100326040550/http://www.honeynet.org.pt:80/index.php/HoneyMole) - Deploy multiple sensors that redirect traffic to a centralized collection of honeypots.

* HTTPS Proxy

  * [mitmproxy](https://mitmproxy.org/) - Allows traffic flows to be intercepted, inspected, modified, and replayed.

* Data Collection

  * [Kippo2MySQL](https://bruteforcelab.com/kippo2mysql) - Extracts some very basic stats from Kippo’s text-based log files and inserts them in a MySQL database.
  * [Kippo2ElasticSearch](https://bruteforcelab.com/kippo2elasticsearch) - Python script to transfer data from a Kippo SSH honeypot MySQL database to an ElasticSearch instance (server or cluster).

* Honeynet data fusion

  * [HFlow2](https://projects.honeynet.org/hflow) - Data coalesing tool for honeynet/network analysis.

* IDS signature generation

  * [Honeycomb](http://www.icir.org/christian/honeycomb/) - Automated signature creation using honeypots.

* Lookup service for AS-numbers and prefixes

  * [CC2ASN](http://www.cc2asn.com/) - Simple lookup service for AS-numbers and prefixes belonging to any given country in the world.

* Central management tool

  * [PHARM](http://www.nepenthespharm.com/) - Manage, report, and analyze your distributed Nepenthes instances.

* Network connection analyzer

  * [Impost](http://impost.sourceforge.net/) - Network security auditing tool designed to analyze the forensics behind compromised and/or vulnerable daemons.

* Honeypot extensions to Wireshark

  * [Wireshark Extensions](https://www.honeynet.org/project/WiresharkExtensions) - Apply Snort IDS rules and signatures against packet capture files using Wireshark.

* Hybrid low/high interaction honeypot

  * [HoneyBrid](http://honeybrid.sourceforge.net)

* Distributed sensor project

  * [DShield Web Honeypot Project](https://sites.google.com/site/webhoneypotsite/)

* A pcap analyzer

  * [Honeysnap](https://projects.honeynet.org/honeysnap/)

* Network traffic redirector

  * [Honeywall](https://projects.honeynet.org/honeywall/)

* Honeypot Distribution with mixed content

  * [HoneyDrive](https://bruteforcelab.com/honeydrive)

* Honeypot sensor

  * [Honeeepi](https://redmine.honeynet.org/projects/honeeepi/wiki) - Honeypot sensor on a Raspberry Pi based on a customized Raspbian OS.

* File carving

  * [TestDisk & PhotoRec](https://www.cgsecurity.org/)

* Behavioral analysis tool for win32

  * [Capture BAT](https://www.honeynet.org/node/315)

* Live CD

  * [DAVIX](https://www.secviz.org/node/89) - The DAVIX Live CD.

* Commercial honeynet

  * [Cymmetria Mazerunner](origin/ttps:/cymmetria.com/products/mazerunner/) - Leads attackers away from real targets and creates a footprint of the attack.

* Dynamic analysis of Android apps

  * [Droidbox](https://code.google.com/archive/p/droidbox/)

* Network analysis

  * [Quechua](https://bitbucket.org/zaccone/quechua)

* SIP Server

  * [Artemnesia VoIP](http://artemisa.sourceforge.net)

## Honeyd Tools

* Honeyd plugin

  * [Honeycomb](http://www.honeyd.org/tools.php)

* Honeyd viewer

  * [Honeyview](http://honeyview.sourceforge.net/)

* Honeyd to MySQL connector

  * [Honeyd2MySQL](https://bruteforcelab.com/honeyd2mysql)

* A script to visualize statistics from honeyd

  * [Honeyd-Viz](https://bruteforcelab.com/honeyd-viz)

* Honeyd stats
  * [Honeydsum.pl](https://github.com/DataSoft/Honeyd/blob/master/scripts/misc/honeydsum-v0.3/honeydsum.pl) ⭐ 391 | 🐛 31 | 🌐 C | 📅 2023-05-20

## Network and Artifact Analysis

* Sandbox

  * [dorothy2](https://github.com/m4rco-/dorothy2) ⭐ 195 | 🐛 1 | 🌐 Ruby | 📅 2023-09-26 - Malware/botnet analysis framework written in Ruby.
  * [libemu](https://github.com/buffer/libemu) ⭐ 154 | 🐛 7 | 🌐 C | 📅 2024-03-27 - Shellcode emulation library, useful for shellcode detection.
  * [Pylibemu](https://github.com/buffer/pylibemu) ⭐ 128 | 🐛 3 | 🌐 Python | 📅 2023-11-29 - Libemu Cython wrapper.
  * [imalse](https://github.com/hbhzwj/imalse) ⭐ 13 | 🐛 1 | 🌐 Tcl | 📅 2013-12-10 - Integrated MALware Simulator and Emulator.
  * [Argos](http://www.few.vu.nl/argos/) - Emulator for capturing zero-day attacks.
  * [COMODO automated sandbox](https://help.comodo.com/topic-72-1-451-4768-.html)
  * [Cuckoo](https://cuckoosandbox.org/) - Leading open source automated malware analysis system.
  * [RFISandbox](https://monkey.org/~jose/software/rfi-sandbox/) - PHP 5.x script sandbox built on top of [funcall](https://pecl.php.net/package/funcall).

* Sandbox-as-a-Service

  * [Hybrid Analysis](https://www.hybrid-analysis.com) - Free malware analysis service powered by Payload Security that detects and analyzes unknown threats using a unique Hybrid Analysis technology.
  * [Joebox Cloud](https://jbxcloud.joesecurity.org/login) - Analyzes the behavior of malicious files including PEs, PDFs, DOCs, PPTs, XLSs, APKs, URLs and MachOs on Windows, Android and Mac OS X for suspicious activities.
  * [VirusTotal](https://www.virustotal.com/) - Analyze suspicious files and URLs to detect types of malware, and automatically share them with the security community.
  * [malwr.com](https://malwr.com/) - Free malware analysis service and community.

## Data Tools

* Visualization

  * [IVRE](https://github.com/ivre/ivre) ⭐ 3,942 | 🐛 53 | 🌐 Python | 📅 2026-01-27 - Network recon framework, published by @cea-sec & @ANSSI-FR. Build your own, self-hosted and fully-controlled alternatives to Criminalip / Shodan / ZoomEye / Censys and GreyNoise, run your Passive DNS service, collect and analyse network intelligence from your sensors, and much more!
  * [HoneyMap](https://github.com/fw42/honeymap) ⭐ 224 | 🐛 9 | 🌐 CoffeeScript | 📅 2016-08-09 - Real-time websocket stream of GPS events on a fancy SVG world map.
  * [The Intelligent HoneyNet](https://github.com/jpyorre/IntelligentHoneyNet) ⭐ 65 | 🐛 1 | 🌐 Python | 📅 2015-11-05 - Create actionable information from honeypots.
  * [ovizart](https://github.com/oguzy/ovizart) ⭐ 49 | 🐛 7 | 🌐 JavaScript | 📅 2013-04-22 - Visual analysis for network traffic.
  * [Kippo stats](https://github.com/mfontani/kippo-stats) ⭐ 19 | 🐛 2 | 🌐 Perl | 📅 2011-05-04 - Mojolicious app to display statistics for your kippo SSH honeypot.
  * [Afterglow Cloud](https://github.com/ayrus/afterglow-cloud) ⭐ 16 | 🐛 0 | 🌐 Perl | 📅 2013-05-04
  * [HpfeedsHoneyGraph](https://github.com/yuchincheng/HpfeedsHoneyGraph) ⭐ 16 | 🐛 0 | 🌐 JavaScript | 📅 2013-02-13 - Visualization app to visualize hpfeeds logs.
  * [HoneyMalt](https://github.com/SneakersInc/HoneyMalt) ⚠️ Archived - Maltego tranforms for mapping Honeypot systems.
  * [Acapulco](https://github.com/hgascon/acapulco) ⭐ 11 | 🐛 0 | 🌐 JavaScript | 📅 2015-10-05 - Automated Attack Community Graph Construction.
  * [Glastopf Analytics](https://github.com/katkad/Glastopf-Analytics) ⭐ 4 | 🐛 0 | 🌐 Perl | 📅 2015-12-14 - Easy honeypot statistics.
  * [Afterglow](http://afterglow.sourceforge.net/)
  * [HoneyStats](https://sourceforge.net/projects/honeystats/) - Statistical view of the recorded activity on a Honeynet.
  * [Kippo-Graph](https://bruteforcelab.com/kippo-graph) - Full featured script to visualize statistics from a Kippo SSH honeypot.

* Front Ends

  * [Tango](https://github.com/aplura/Tango) ⭐ 256 | 🐛 22 | 🌐 Shell | 📅 2018-10-18 - Honeypot Intelligence with Splunk.
  * [DionaeaFR](https://github.com/rubenespadas/DionaeaFR) ⭐ 68 | 🐛 20 | 🌐 Python | 📅 2017-08-07 - Front Web to Dionaea low-interaction honeypot.
  * [Django-kippo](https://github.com/jedie/django-kippo) ⭐ 13 | 🐛 0 | 🌐 Python | 📅 2012-07-09 - Django App for kippo SSH Honeypot.
  * [Wordpot-Frontend](https://github.com/GovCERT-CZ/Wordpot-Frontend) ⚠️ Archived - Full featured script to visualize statistics from a Wordpot honeypot.
  * [Shockpot-Frontend](https://github.com/GovCERT-CZ/Shockpot-Frontend) ⚠️ Archived - Full featured script to visualize statistics from a Shockpot honeypot.
  * [honeypotDisplay](https://github.com/Joss-Steward/honeypotDisplay) ⭐ 4 | 🐛 0 | 🌐 JavaScript | 📅 2016-02-05 - Flask website which displays data gathered from an SSH Honeypot.
  * [honeyalarmg2](https://github.com/schmalle/honeyalarmg2) - Simplified UI for showing honeypot alarms.

## Guides

* [Honeypot (Dionaea and kippo) setup script](https://github.com/andrewmichaelsmith/honeypot-setup-script/) ⭐ 83 | 🐛 5 | 🌐 Shell | 📅 2016-11-09

* Deployment

  * [honeypotpi](https://github.com/free5ty1e/honeypotpi) ⭐ 35 | 🐛 0 | 🌐 Shell | 📅 2024-09-25 - Script for turning a Raspberry Pi into a HoneyPot Pi.
  * [Dionaea and EC2 in 20 Minutes](http://andrewmichaelsmith.com/2012/03/dionaea-honeypot-on-ec2-in-20-minutes/) - Tutorial on setting up Dionaea on an EC2 instance.
  * [Using a Raspberry Pi honeypot to contribute data to DShield/ISC](https://isc.sans.edu/diary/22680) - The Raspberry Pi based system will allow us to maintain one code base that will make it easier to collect rich logs beyond firewall logs.

* Research Papers

  * [Honeypot research papers](https://github.com/shbhmsingh72/Honeypot-Research-Papers) ⭐ 34 | 🐛 0 | 📅 2018-06-02 - PDFs of research papers on honeypots.
  * [vEYE](https://link.springer.com/article/10.1007%2Fs10115-008-0137-3) - Behavioral footprinting for self-propagating worm detection and profiling.

* [T-Pot: A Multi-Honeypot Platform](https://dtag-dev-sec.github.io/mediator/feature/2015/03/17/concept.html)
