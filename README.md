<!-- ================================================= -->
<!--              Cybersecurity Portfolio              -->
<!-- ================================================= -->

<p align="center">
  <img src="https://img.shields.io/badge/Focus-Cybersecurity-critical?style=for-the-badge">
  <img src="https://img.shields.io/badge/Level-Student-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Status-Active%20Learning-success?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Linux-Security-black?style=flat-square&logo=linux&logoColor=white">
  <img src="https://img.shields.io/badge/Web%20Security-AppSec-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Pentest-Offensive-red?style=flat-square">
  <img src="https://img.shields.io/badge/Blue%20Team-Defensive-informational?style=flat-square">
</p>

---

# 👋 Olá, eu sou o Tiago

Sou estudante de Engenharia de Software, com foco em Cibersegurança, especialmente em segurança ofensiva, análise de vulnerabilidades, aplicações web, redes e ambientes Linux.

Este repositório funciona como meu portfólio técnico, reunindo documentações de estudo, laboratórios práticos, análises de vulnerabilidades reais (CVEs), testes controlados em ambientes de laboratório e anotações técnicas, com foco em compreender o funcionamento dos ataques, suas causas e as formas adequadas de mitigação.

---

## 📂 Projetos e Documentações

### 📋 Checklists & Metodologias

- [Pentest Checklist — Metodologia Prática](https://github.com/tiago4lexandre/Pentest-Checklist)
  Checklist estruturado para testes de penetração, cobrindo as fases de reconhecimento, enumeração, exploração, pós-exploração e reporte, com foco em organização, repetibilidade e boas práticas.
  `Pentest · Methodology · Checklist · Reconnaissance · Enumeration · Exploitation · Reporting`

---

### ⚛️ Vulnerabilidades Reais (CVE)

- [React2Shell — CVE-2025-55182](https://github.com/tiago4lexandre/React2Shell)
  Análise completa de vulnerabilidade crítica em aplicações **Next.js / React**, explorando desserialização insegura, prototype pollution e **Remote Code Execution (RCE)**.
  `AppSec · RCE · JavaScript · Next.js`

- [Dirty Pipe — CVE-2022-0847](https://github.com/tiago4lexandre/Dirty-Pipe-CVE-2022-0847)
  Análise técnica e exploração prática de vulnerabilidade crítica no **kernel Linux**, permitindo **elevação de privilégios local até root** por meio da sobrescrita de arquivos somente leitura e abuso de buffers de pipe.
  `Linux Kernel · Privilege Escalation · CVE · Kernel Exploitation · Red Team`

---

### 🐧 Linux Security

- [Linux Privilege Escalation](https://github.com/tiago4lexandre/Linux-Privilege-Escalation)
  Técnicas de enumeração, exploração e mitigação de falhas locais em sistemas Linux.
  `Privilege Escalation · Post-Exploitation · Hardening`

- [Reverse Shell — Estabilização de TTY](https://github.com/tiago4lexandre/Stable-ReverseShell)
  Guia completo sobre criação, upgrade e estabilização de shells interativos.
  `Post-Exploitation · Networking · Linux`

---

### 🌐 Network Security

- [ARP Spoofing & Man-in-the-Middle com BetterCap](https://github.com/tiago4lexandre/ARP-Spoofing-MITM)
  Documentação técnica e prática sobre ataques Man-in-the-Middle via ARP Spoofing em redes locais, abordando fundamentos de redes, interceptação e manipulação de tráfego, sniffing, proxy HTTP/HTTPS, SSL Stripping, detecção e mitigação.
  `Network Security · ARP Spoofing · MITM · BetterCap · Sniffing · Blue Team · Red Team`

---

### 🛠️ Ferramentas de Segurança

- [Gobuster — Web Enumeration](https://github.com/tiago4lexandre/GoBuster)
  Documentação técnica e prática sobre enumeração ativa em aplicações web, utilizando Gobuster para descoberta de diretórios, arquivos sensíveis, subdomínios DNS e virtual hosts durante a fase de reconhecimento em testes de penetração.
  `Web Security · Reconnaissance · Enumeration · Gobuster · Pentest`

- [Hydra — Credential Attacks & Authentication Testing](https://github.com/tiago4lexandre/Hydra)
  Documentação técnica e prática sobre o uso do **THC-Hydra** em testes de autenticação, abordando ataques de força bruta e password spraying contra serviços web e de rede, com foco em metodologia ofensiva, impacto e medidas de mitigação.
  `Password Attacks · Brute Force · Credential Testing · Web · Network · Pentest`

- [John The Ripper — Password Auditing](https://github.com/tiago4lexandre/John-The-Ripper)
  Estudo aprofundado sobre hashes, cracking, auditoria de senhas e boas práticas defensivas. 
  `Hashing · Cryptography · Linux · Windows`

---

### 🧪 Laboratórios Práticos

- [Linux Privilege Escalation — TryHackMe](https://github.com/tiago4lexandre/THM-LinuxPrivilegeEscalation)
  Laboratório prático focado em **pós-exploração em ambientes Linux**, abordando enumeração manual e automatizada, identificação de **vulnerabilidades de kernel**, análise de **CVEs reais** e exploração prática para obtenção de privilégios **root**, com validação e análise técnica do impacto.
  `Post-Exploitation · Linux PrivEsc · Kernel Exploitation · CVE · Enumeration`

- ✅ [Mr. Robot — TryHackMe](https://github.com/tiago4lexandre/Mr-Robot)
  Relatório técnico completo de **Web Pentest e Linux Privilege Escalation**, cobrindo todo o ciclo ofensivo desde **reconhecimento e enumeração**, exploração de **WordPress**, **força bruta de credenciais**, **execução remota de código**, **quebra de hash**, **movimento lateral** e **escalonamento final para root** via binário **SUID**, com análise de impacto e recomendações de mitigação baseadas em boas práticas de segurança.
  `Web Pentest · WordPress · Brute Force · Hydra · RCE · Hash Cracking · SUID · Linux PrivEsc · PTES`

- ✅ [Gallery — TryHackMe](https://github.com/tiago4lexandre/Gallery)
  Laboratório prático de Web Pentest envolvendo enumeração de aplicação, exploração de SQL Injection, File Upload malicioso, obtenção de Reverse Shell e escalonamento de privilégios em ambiente Linux.
  `Web Pentest · SQL Injection · File Upload · Reverse Shell · Linux PrivEsc`

- ✅ [PwnLab: Init — Web Pentest Lab](https://github.com/tiago4lexandre/PWNLAB)
  Exploração completa de aplicação web vulnerável até obtenção de root.
  `LFI · File Upload · Reverse Shell · PrivEsc`
  
- ✅ [Break Out The Cage — TryHackMe](https://github.com/tiago4lexandre/Break-Out-The-Cage)
  Laboratório prático focado em enumeração de serviços, criptoanálise, esteganografia e escalonamento de privilégios em ambiente Linux, explorando falhas de configuração, scripts inseguros e tarefas automatizadas.
  `Enumeration · Cryptography · Steganography · Post-Exploitation · Linux PrivEsc`

---

## 🛠️ Ferramentas e Tecnologias

- **Sistemas:** Linux, Windows
- **Web:** HTTP, REST, Next.js, React
- **Linguagens:** Python, Bash, JavaScript
- **Ferramentas:** Burp Suite, Nmap, Netcat, Socat, John The Ripper
- **Ambientes:** TryHackMe, VulnHub, Labs locais

---

## 📈 Em evolução

Este portfólio está em **constante atualização**, acompanhando minha evolução na área de cibersegurança.

Novos conteúdos planejados:
- Windows Privilege Escalation
- Active Directory
- Web Exploitation avançado
- Detecção e resposta (Blue Team)
- Análise de logs e incidentes

---

## 📫 Contato

- 🔗 **LinkedIn:** https://www.linkedin.com/in/tiago-alexandre2001
- 💻 **GitHub:** https://github.com/tiago4lex

---

> ⚠️ Todo o conteúdo aqui apresentado é utilizado **exclusivamente para fins educacionais e ambientes autorizados**.
