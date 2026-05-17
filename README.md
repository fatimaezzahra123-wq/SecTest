<div align="center">

# 🔐 SecTest Generator

### AI-Powered Security Regression Test Generator for DevSecOps Pipelines

[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.0-brightgreen?style=for-the-badge&logo=springboot)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-17-orange?style=for-the-badge&logo=openjdk)](https://adoptium.net/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-blue?style=for-the-badge&logo=mysql)](https://www.mysql.com/)
[![Ollama](https://img.shields.io/badge/AI-Ollama%20llama3.2-purple?style=for-the-badge)](https://ollama.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-SecTest-black?style=for-the-badge&logo=github)](https://github.com/fatimaezzahra123-wq/SecTest)

**National School of Applied Sciences — cadi ayad University, Marrakech, Morocco**


</div>

---

## 🎬 Demo Video

> **Watch SecTest Generator in action**

[![Demo Video](https://img.shields.io/badge/▶%20Watch%20Demo-YouTube-red?style=for-the-badge&logo=youtube)](https://youtu.be/CyryhNbXYK0)

**What the demo covers:**
- ✅ Source code analysis — VulnerableApp.java (15 vulnerabilities, score 0/100)
- ✅ Android APK analysis — InsecureBankv2.apk (19 vulnerabilities, exported components)
- ✅ AI prioritization and MASVS/MASTG mapping via Ollama
- ✅ Auto-generated JUnit 5 regression tests
- ✅ Security Gate BLOCKED/PASSED decision
- ✅ PDF report generation
- ✅ Analytics Dashboard with charts

> 📌 *Replace `https://youtu.be/CyryhNbXYK0` with your YouTube or Google Drive video link*

---

## 📋 Table of Contents

- [Description](#-description)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
- [Usage](#-usage)
- [Security Rules](#-security-rules-coverage)
- [AI Features](#-ai-features-ollama)
- [API Reference](#-rest-api)
- [Project Structure](#-project-structure)
- [Authors](#-authors)
- [License](#-license)

---

## 📖 Description

**SecTest Generator** is an open-source DevSecOps platform that automatically analyzes source code and Android APK files to detect security vulnerabilities, generate JUnit regression tests, and enforce a Security Gate in CI/CD pipelines.

The platform combines:
- 🔍 **Static analysis engine** with 46 security rules across Java, Python, and JavaScript
- 📱 **Android APK analysis** with APKTool decompilation and MASVS mapping
- 🤖 **Local AI inference** via Ollama llama3.2 for intelligent vulnerability prioritization
- 🧪 **Automatic JUnit 5 test generation** for regression prevention
- 🚦 **Security Gate** that blocks deployment when critical vulnerabilities are detected

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Multi-language Analysis** | Java (20 rules), Python (12 rules), JavaScript (14 rules) |
| 📱 **APK Analysis** | Permissions, exported components, cleartext, debug mode |
| 🤖 **AI Prioritization** | Ollama llama3.2 orders vulnerabilities by urgency |
| 🗺️ **MASVS Mapping** | Maps findings to OWASP MASVS/MASTG controls |
| 🧪 **JUnit Generation** | Auto-generates executable regression tests |
| 🚦 **Security Gate** | BLOCKED if CRITICAL vulnerabilities detected |
| 📊 **Dashboard** | Charts: severity donut, category bar, score evolution |
| 📄 **PDF Reports** | Professional reports with iText library |
| 🗄️ **Scan History** | All results stored and searchable in MySQL |
| 🔒 **Privacy-first** | Local AI — source code never leaves your machine |

---

## 🛠️ Tech Stack

```
┌─────────────────────────────────────────────────────────┐
│                    FRONTEND                              │
│         HTML5 + JavaScript + Chart.js                   │
├─────────────────────────────────────────────────────────┤
│                    BACKEND                               │
│         Java 17 + Spring Boot 3.2 + REST API            │
├──────────────────────┬──────────────────────────────────┤
│      ANALYSIS        │           AI                     │
│  CodeAnalyzerService │      OllamaService               │
│  ApkAnalyzerService  │      llama3.2 (local)            │
│  APKTool 3.0.2       │                                  │
├──────────────────────┴──────────────────────────────────┤
│                    DATABASE                              │
│              MySQL 8.0 + JPA/Hibernate                  │
└─────────────────────────────────────────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites

| Tool | Version | Download |
|---|---|---|
| Java (Temurin) | 17+ | [adoptium.net](https://adoptium.net/temurin/releases/?version=17) |
| Maven | 3.9+ | [maven.apache.org](https://maven.apache.org/download.cgi) |
| MySQL (XAMPP) | 8.0 | [apachefriends.org](https://www.apachefriends.org/) |
| Ollama *(optional)* | Latest | [ollama.com](https://ollama.com/download) |

### Installation

**Step 1 — Clone the repository**
```bash
git clone https://github.com/fatimaezzahra123-wq/SecTest.git
cd SecTest
```

**Step 2 — Create the database**
```sql
CREATE DATABASE security_db;

-- If column too small error occurs:
USE security_db;
ALTER TABLE scan_results MODIFY COLUMN generated_tests LONGTEXT;
```

**Step 3 — Configure application**

Edit `src/main/resources/application.properties`:
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/security_db
spring.datasource.username=root
spring.datasource.password=YOUR_PASSWORD
spring.jpa.hibernate.ddl-auto=update
spring.servlet.multipart.max-file-size=50MB
spring.servlet.multipart.max-request-size=50MB
```

**Step 4 — Install Ollama AI** *(optional but recommended)*
```bash
# Download from https://ollama.com/download
ollama pull llama3.2
ollama serve
```

**Step 5 — Run the application**

```powershell
# Windows PowerShell (Run as Administrator)
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot"
$env:Path = "$env:JAVA_HOME\bin;" + $env:Path
mvn spring-boot:run
```

```bash
# Linux / macOS
export JAVA_HOME=/path/to/jdk-17
mvn spring-boot:run
```

**Step 6 — Open the application**

👉 **http://localhost:8080**

---

## 📖 Usage

### Analyze Source Code

```
1. Open http://localhost:8080
2. Click "Code Source" tab
3. Upload .java / .py / .js / .ts file
4. Click "Analyze"
5. View results → Download PDF
```

### Analyze Android APK

```
1. Click "Fichier APK" tab
2. Upload .apk file
3. Click "Analyze"
4. View permissions, exported components, MASVS mapping
5. Download PDF report
```

### Sample Test Files

| File | Type | Expected Result |
|---|---|---|
| `VulnerableApp.java` | Java | 15 vulns, Score 0/100, BLOCKED |
| `InsecureBankv2.apk` | APK | 19 vulns, Score 0/100, BLOCKED |
| `dvba.apk` | APK | 10 vulns, exported components |

---

## 🔍 Security Rules Coverage

### Source Code Rules

| Language | Total Rules | CRITICAL | HIGH | MEDIUM | LOW |
|---|---|---|---|---|---|
| Java | 20 | 5 | 8 | 4 | 3 |
| Python | 12 | 4 | 5 | 2 | 1 |
| JavaScript | 14 | 5 | 6 | 2 | 1 |

**Detected vulnerability types:**

| CWE | Vulnerability | Severity |
|---|---|---|
| CWE-89 | SQL Injection | CRITICAL |
| CWE-78 | Command Injection | CRITICAL |
| CWE-611 | XXE Injection | CRITICAL |
| CWE-502 | Insecure Deserialization | CRITICAL |
| CWE-798 | Hardcoded Secrets | HIGH |
| CWE-22 | Path Traversal | HIGH |
| CWE-328 | Weak Hash (MD5/SHA1) | HIGH |
| CWE-295 | SSL Not Verified | HIGH |
| CWE-338 | Insecure Random | MEDIUM |
| CWE-209 | printStackTrace | LOW |

### Android APK Rules

| Category | Rules | Severity |
|---|---|---|
| Dangerous Permissions | 9 CRITICAL, 14 HIGH, 8 MEDIUM | CRITICAL-MEDIUM |
| Exported Components | Activity, Service, Receiver, Provider | CRITICAL |
| Cleartext Traffic | usesCleartextTraffic | CRITICAL |
| Debug Mode | android:debuggable | CRITICAL |
| Insecure Storage | SharedPreferences, SQLite | HIGH |
| Weak SSL | TrustAllCerts, HostnameVerifier | CRITICAL |
| Backup Enabled | android:allowBackup | HIGH |

---

## 🤖 AI Features (Ollama)

When Ollama is running locally, the platform enriches analysis with:

### Vulnerability Prioritization
```
1. [CRITICAL] Command Injection → Fix immediately
2. [CRITICAL] SQL Injection → Fix immediately
3. [HIGH] Hardcoded Password → Fix this sprint
4. [HIGH] Weak Hash MD5 → Fix this sprint
```

### MASVS Android Mapping
```
- SEND_SMS (CWE-250)     → MASVS-CODE-4
- Exported SendMoney      → MASVS-PLATFORM-1
- Cleartext Traffic       → MASVS-NETWORK-1
- READ_CONTACTS (CWE-250) → MASVS-IDENTITY-2
```

### Network Security Config Generation
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>
</network-security-config>
```

---

## 📊 Security Score

```
Score = max(0, 100 - CRITICAL×25 - HIGH×10 - MEDIUM×5 - LOW×2)
```

| Score Range | Status | Security Gate | Color |
|---|---|---|---|
| 80 — 100 | Secure ✅ | PASSED | 🟢 Green |
| 50 — 79 | Medium ⚠️ | PASSED | 🟡 Yellow |
| 0 — 49 | Critical ❌ | BLOCKED | 🔴 Red |

---

## 🌐 REST API

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Check API status |
| `/api/analyze` | POST | Upload and analyze file |
| `/api/history` | GET | Get all scan history |
| `/api/history/{id}` | GET | Get specific scan by ID |
| `/api/report/{id}/pdf` | GET | Download PDF report |

### Example Request
```bash
curl -X POST http://localhost:8080/api/analyze \
  -F "file=@VulnerableApp.java"
```

### Example Response
```json
{
  "id": 1,
  "fileName": "VulnerableApp.java",
  "securityScore": 0,
  "gateStatus": "BLOCKED",
  "criticalCount": 6,
  "highCount": 6,
  "mediumCount": 2,
  "lowCount": 1,
  "vulnerabilities": [...]
}
```

---

## 📁 Project Structure

```
SecTest/
├── src/
│   └── main/
│       ├── java/com/security/
│       │   ├── SecurityApplication.java       # Entry point
│       │   ├── controller/
│       │   │   └── SecurityController.java    # REST API
│       │   ├── model/
│       │   │   ├── ScanResult.java            # Scan entity
│       │   │   └── Vulnerability.java         # Vuln entity
│       │   ├── repository/
│       │   │   └── ScanResultRepository.java  # DB access
│       │   └── service/
│       │       ├── ScanService.java           # Orchestrator
│       │       ├── CodeAnalyzerService.java   # Code analysis
│       │       ├── ApkAnalyzerService.java    # APK analysis
│       │       ├── OllamaService.java         # AI service
│       │       ├── TestGeneratorService.java  # JUnit generator
│       │       └── PdfReportService.java      # PDF generator
│       └── resources/
│           ├── application.properties         # Config
│           ├── apktool.jar                    # APKTool binary
│           └── static/
│               └── index.html                 # Web UI
├── pom.xml                                    # Dependencies
└── README.md
```

---

## 👥 Authors

<div align="center">

| Name | Role |
|---|---|
| **Hiba Chagdaly** | Developer |
| **Sara Jamiri** | Developer |
| **Malak Lahnine** | Developer |
| **Fatimaezzahra Ennassiri** | Developer |

**Institution:** National School of Applied Sciences  
**University:** Chouaib Doukkali University, El Jadida, Morocco  
**Year:** 2025-2026

</div>

---

## 📄 License

This project is licensed under the **MIT License**.

```
MIT License — Copyright (c) 2026 SecTest Team
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software.
```

---

## 🙏 Acknowledgements

- [OWASP MASVS](https://mas.owasp.org/MASVS/) — Mobile Application Security Verification Standard
- [APKTool](https://apktool.org/) — Android APK decompilation
- [Ollama](https://ollama.com/) — Local AI inference engine
- [Spring Boot](https://spring.io/) — Java backend framework
- [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) — Test APK

---

<div align="center">


Made with ❤️ by SecTest Team — ENSA Marrakesh

</div>
