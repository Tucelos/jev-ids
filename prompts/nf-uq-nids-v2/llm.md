# Overview

You are given one record of a network connection, described by the columns listed below. Decide whether the connection is an intrusion attempt or normal traffic, and which category it belongs to. Labeled example records may be provided; use them as reference. Judge the record by its own values: do not assume a category is present only because it appears among the examples.

# Categories

- `Benign`: legitimate traffic.
- `Analysis`: a group of intrusions that probe web applications through ports, e-mails and scripts.
- `Backdoor`: a technique that bypasses normal authentication to gain remote access to a host.
- `Bot`: traffic of a compromised host controlled remotely as part of a botnet.
- `Brute Force`: repeated guesses of credentials against a login service such as SSH, FTP or a web form.
- `DDoS`: distributed denial of service, flooding a target from many sources at once.
- `DoS`: denial of service, an attempt to make a host or service too busy or too broken to serve legitimate requests.
- `Exploits`: a sequence of instructions that takes advantage of a known vulnerability in software or an operating system.
- `Fuzzers`: feeding a program or network randomly generated data to make it crash or hang.
- `Generic`: an attack against block ciphers that works whatever the cipher's structure, such as collision attacks.
- `Infilteration`: an attack from inside the network after a host is compromised, typically through a malicious file, followed by scanning of the rest of the network.
- `Injection`: insertion of malicious input, such as SQL statements or commands, into an application to alter what it executes.
- `MITM`: man in the middle, intercepting and possibly altering the traffic between two parties.
- `Password`: attacks against passwords, including brute-force and dictionary guessing.
- `Ransomware`: malware that encrypts a victim's data and demands payment.
- `Reconnaissance`: surveillance or scanning that gathers information about hosts, ports or services.
- `Scanning`: systematic probing of ports or hosts to discover running services.
- `Shellcode`: a small piece of code used as the payload when exploiting a software vulnerability.
- `Theft`: data exfiltration or keylogging from a compromised host.
- `Worms`: self-replicating malware that spreads to other hosts over the network.
- `XSS`: cross-site scripting, injecting client-side scripts into web pages viewed by other users.

# Columns of a record (in order)

L4_SRC_PORT,L4_DST_PORT,PROTOCOL,L7_PROTO,IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS,FLOW_DURATION_MILLISECONDS,TCP_FLAGS,CLIENT_TCP_FLAGS,SERVER_TCP_FLAGS,DURATION_IN,DURATION_OUT,MIN_TTL,MAX_TTL,LONGEST_FLOW_PKT,SHORTEST_FLOW_PKT,MIN_IP_PKT_LEN,MAX_IP_PKT_LEN,SRC_TO_DST_SECOND_BYTES,DST_TO_SRC_SECOND_BYTES,RETRANSMITTED_IN_BYTES,RETRANSMITTED_IN_PKTS,RETRANSMITTED_OUT_BYTES,RETRANSMITTED_OUT_PKTS,SRC_TO_DST_AVG_THROUGHPUT,DST_TO_SRC_AVG_THROUGHPUT,NUM_PKTS_UP_TO_128_BYTES,NUM_PKTS_128_TO_256_BYTES,NUM_PKTS_256_TO_512_BYTES,NUM_PKTS_512_TO_1024_BYTES,NUM_PKTS_1024_TO_1514_BYTES,TCP_WIN_MAX_IN,TCP_WIN_MAX_OUT,ICMP_TYPE,ICMP_IPV4_TYPE,DNS_QUERY_ID,DNS_QUERY_TYPE,DNS_TTL_ANSWER,FTP_COMMAND_RET_CODE

# Examples

{examples}

# Complementary Information

Answer only with a JSON object with three fields: "verdict" ("attack" or "normal"), "category" (one of Benign, Analysis, Backdoor, Bot, Brute Force, DDoS, DoS, Exploits, Fuzzers, Generic, Infilteration, Injection, MITM, Password, Ransomware, Reconnaissance, Scanning, Shellcode, Theft, Worms, XSS) and "p_attack" (your probability, between 0 and 1, that the record is an attack).
