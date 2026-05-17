# 🔒 Security Regression Test Generator
## Projet 13 — DevSecOps | Spring Boot REST API

> Outil de génération automatique de tests de sécurité intégré dans un pipeline CI/CD GitHub Actions.  
> Analyse du **code source** (Java, Python, JavaScript) et des **fichiers APK Android**.

---

## 🏗️ Architecture

```
security-regression-tool/
│
├── src/main/java/com/security/
│   ├── controller/
│   │   └── SecurityController.java    ← API REST (tous les endpoints)
│   ├── service/
│   │   ├── CodeAnalyzerService.java   ← Analyse Java/Python/JS
│   │   ├── ApkAnalyzerService.java    ← Analyse fichiers APK
│   │   ├── TestGeneratorService.java  ← Génère tests JUnit
│   │   ├── PdfReportService.java      ← Génère rapports PDF (iText)
│   │   └── ScanService.java           ← Orchestre tout
│   ├── model/
│   │   ├── ScanResult.java            ← Entité scan (MySQL)
│   │   └── Vulnerability.java         ← Entité vulnérabilité
│   ├── repository/
│   │   └── ScanResultRepository.java  ← JPA Repository
│   └── SecurityApplication.java       ← Point d'entrée
│
├── src/main/resources/
│   ├── application.properties         ← Config Spring Boot + MySQL
│   └── static/index.html              ← Interface web
│
├── .github/workflows/
│   └── security-tests.yml             ← Pipeline GitHub Actions
│
├── Dockerfile                          ← Conteneur Spring Boot
├── docker-compose.yml                  ← Spring Boot + MySQL
└── pom.xml                             ← Dépendances Maven
```

---

## 🚀 Lancement avec Docker

```bash
# 1. Cloner le projet
git clone https://github.com/<username>/security-regression-tool.git
cd security-regression-tool

# 2. Lancer tout (Spring Boot + MySQL)
docker-compose up --build

# 3. Accéder à l'interface web
http://localhost:8080

# 4. Tester l'API
curl http://localhost:8080/api/health
```

---

## 📡 API REST Endpoints

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/api/analyze` | Analyser un fichier (code ou APK) |
| `GET` | `/api/report/{id}/pdf` | Télécharger le rapport PDF |
| `GET` | `/api/tests/{id}` | Récupérer les tests JUnit générés |
| `GET` | `/api/history` | Historique de tous les scans |
| `GET` | `/api/history/{id}` | Détail d'un scan |
| `GET` | `/api/health` | Statut de l'API |

### Exemple d'appel API

```bash
# Analyser un fichier Java
curl -X POST http://localhost:8080/api/analyze \
  -F "file=@VulnerableApp.java"

# Analyser un APK
curl -X POST http://localhost:8080/api/analyze \
  -F "file=@myapp.apk"

# Télécharger le rapport PDF
curl -O http://localhost:8080/api/report/1/pdf
```

---

## 🔍 Vulnérabilités détectées

### Code Source (Java/Python/JavaScript)
| ID | Vulnérabilité | Sévérité | CWE |
|----|--------------|----------|-----|
| JV001/PY001/JS001 | SQL Injection | 🔴 CRITICAL | CWE-89 |
| JV002/PY002/JS002 | Hardcoded Secret | 🟠 HIGH | CWE-798 |
| JV003/PY003/JS005 | Command Injection | 🔴 CRITICAL | CWE-78 |
| JV004/PY004 | Weak Hash (MD5/SHA1) | 🟠 HIGH | CWE-328 |
| JV005/PY008/JS007 | Path Traversal | 🟠 HIGH | CWE-22 |
| JV006/PY007/JS006 | Insecure Random | 🟡 MEDIUM | CWE-338 |
| JV007/PY008/JS003 | XSS | 🟠 HIGH | CWE-79 |
| JV008 | XXE Injection | 🔴 CRITICAL | CWE-611 |
| PY006 | Insecure Deserialization | 🔴 CRITICAL | CWE-502 |
| JS004 | Dangerous eval() | 🔴 CRITICAL | CWE-95 |
| JS008 | Prototype Pollution | 🟠 HIGH | CWE-1321 |

### Fichiers APK Android
| Vulnérabilité | Sévérité | CWE |
|--------------|----------|-----|
| Certificat SSL non vérifié | 🔴 CRITICAL | CWE-295 |
| Permissions dangereuses (SMS, CALL) | 🔴 CRITICAL | CWE-250 |
| HTTP non sécurisé | 🟠 HIGH | CWE-319 |
| Stockage non chiffré | 🟠 HIGH | CWE-312 |
| Clés API hardcodées | 🟠 HIGH | CWE-798 |
| WebView JS activé | 🟡 MEDIUM | CWE-79 |
| Log de données sensibles | 🟡 MEDIUM | CWE-532 |
| Mode Debug activé | 🟡 MEDIUM | CWE-215 |

---

## 🛠️ Technologies

| Couche | Technologie |
|--------|-------------|
| **Backend** | Java 17 + Spring Boot 3.2 |
| **API** | Spring Web REST |
| **Base de données** | MySQL 8.0 + Spring Data JPA |
| **PDF** | iText 5 |
| **Frontend** | HTML5 + CSS3 + JavaScript |
| **Conteneurs** | Docker + Docker Compose |
| **CI/CD** | GitHub Actions |
| **Tests** | JUnit 5 + Spring Boot Test |

---

## 📊 Score de Sécurité

```
Score = max(0, 100 - (CRITICAL×25 + HIGH×10 + MEDIUM×5 + LOW×2))

80-100 → ✅ Bon
50-79  → ⚠️ Moyen  
0-49   → ❌ Critique
```

---

## 👥 Auteurs

Projet réalisé dans le cadre du cours **Développement Mobile — DevSecOps**.
