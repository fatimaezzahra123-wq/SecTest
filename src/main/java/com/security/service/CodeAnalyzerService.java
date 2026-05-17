package com.security.service;

import com.security.model.Vulnerability;
import org.springframework.stereotype.Service;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class CodeAnalyzerService {

    // ── SECURITY RULES ────────────────────────────────────────────
    private static final List<Map<String, String>> JAVA_RULES = List.of(
        rule("JV001", "SQL Injection", "CRITICAL", "Injection",
            ".*Statement.*execute.*\\+.*|.*createQuery.*\\+.*",
            "CWE-89", "Utilisez PreparedStatement avec des paramètres: pstmt.setString(1, userInput)",
            "sql_injection"),
        rule("JV002", "Hardcoded Secret", "HIGH", "Secret Exposure",
            "(?i)(password|secret|apikey|token|passwd)\\s*=\\s*\"[^\"]{4,}\"",
            "CWE-798", "Utilisez des variables d'environnement: System.getenv(\"SECRET_KEY\")",
            "hardcoded_secret"),
        rule("JV003", "Command Injection", "CRITICAL", "Injection",
            "Runtime\\.getRuntime\\(\\)\\.exec\\(.*\\+|ProcessBuilder.*\\+",
            "CWE-78", "N'utilisez jamais de données utilisateur dans exec(). Utilisez une liste d'arguments.",
            "command_injection"),
        rule("JV004", "Weak Hash MD5/SHA1", "HIGH", "Cryptography",
            "MessageDigest\\.getInstance\\(\"(MD5|SHA-1|SHA1)\"\\)",
            "CWE-328", "Utilisez SHA-256 ou bcrypt: MessageDigest.getInstance(\"SHA-256\")",
            "weak_hash"),
        rule("JV005", "Path Traversal", "HIGH", "File Access",
            "new File\\(.*\\+|Paths\\.get\\(.*\\+",
            "CWE-22", "Validez le chemin: path.normalize().startsWith(basePath)",
            "path_traversal"),
        rule("JV006", "Insecure Random", "MEDIUM", "Cryptography",
            "new Random\\(\\)|Math\\.random\\(\\)",
            "CWE-338", "Utilisez SecureRandom: new SecureRandom()",
            "weak_random"),
        rule("JV007", "XSS — Unescaped Output", "HIGH", "XSS",
            "response\\.getWriter\\(\\)\\.print.*request\\.getParameter|PrintWriter.*getParameter",
            "CWE-79", "Encodez la sortie: ESAPI.encoder().encodeForHTML(userInput)",
            "xss"),
        rule("JV008", "XXE Injection", "CRITICAL", "Injection",
            "DocumentBuilderFactory\\.newInstance\\(\\)(?!.*setFeature)|SAXParserFactory\\.newInstance\\(\\)(?!.*setFeature)",
            "CWE-611", "Désactivez les entités externes: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
            "xxe")
    );

    private static final List<Map<String, String>> PYTHON_RULES = List.of(
        rule("PY001", "SQL Injection", "CRITICAL", "Injection",
            "execute\\s*\\(\\s*[\"'].*?\\+|execute\\s*\\(\\s*f[\"']",
            "CWE-89", "Utilisez des requêtes paramétrées: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "sql_injection"),
        rule("PY002", "Hardcoded Secret", "HIGH", "Secret Exposure",
            "(?i)(password|secret|api_key|token|passwd)\\s*=\\s*[\"'][^\"']{4,}[\"']",
            "CWE-798", "Utilisez os.environ.get('SECRET_KEY')",
            "hardcoded_secret"),
        rule("PY003", "Command Injection", "CRITICAL", "Injection",
            "subprocess\\.(run|call|Popen).*shell\\s*=\\s*True|os\\.system\\(",
            "CWE-78", "Utilisez shell=False avec une liste: subprocess.run(['ping', host])",
            "command_injection"),
        rule("PY004", "Weak Hash", "HIGH", "Cryptography",
            "hashlib\\.(md5|sha1)\\s*\\(",
            "CWE-328", "Utilisez bcrypt ou hashlib.sha256",
            "weak_hash"),
        rule("PY005", "Insecure Deserialization", "CRITICAL", "Deserialization",
            "pickle\\.(loads|load)\\s*\\(",
            "CWE-502", "Utilisez json.loads() — ne jamais désérialiser des données non fiables",
            "insecure_deserialization"),
        rule("PY006", "Insecure Random", "MEDIUM", "Cryptography",
            "random\\.(randint|random|choice)\\s*\\(",
            "CWE-338", "Utilisez secrets.token_hex() pour les tokens de sécurité",
            "weak_random"),
        rule("PY007", "XSS", "HIGH", "XSS",
            "f[\"'].*<.*?\\{[\\w_]+\\}.*>[\"']",
            "CWE-79", "Utilisez html.escape() ou Jinja2 avec auto-échappement",
            "xss"),
        rule("PY008", "Path Traversal", "HIGH", "File Access",
            "open\\s*\\(\\s*[\\w\\s]*\\+|open\\s*\\(\\s*f[\"']",
            "CWE-22", "Validez le chemin avec os.path.abspath()",
            "path_traversal")
    );

    private static final List<Map<String, String>> JS_RULES = List.of(
        rule("JS001", "SQL Injection", "CRITICAL", "Injection",
            "[\"']SELECT.*WHERE.*[\"']\\s*\\+\\s*\\w+|`SELECT.*\\$\\{",
            "CWE-89", "Utilisez des requêtes paramétrées ou un ORM",
            "sql_injection"),
        rule("JS002", "Hardcoded Secret", "HIGH", "Secret Exposure",
            "(?i)(password|secret|api_?key|token)\\s*=\\s*[\"'][^\"']{4,}[\"']",
            "CWE-798", "Utilisez process.env.SECRET_KEY",
            "hardcoded_secret"),
        rule("JS003", "XSS DOM", "HIGH", "XSS",
            "(innerHTML|outerHTML|document\\.write)\\s*=.*req\\.(query|body|params)",
            "CWE-79", "Utilisez textContent ou sanitisez avec DOMPurify",
            "xss"),
        rule("JS004", "Dangerous eval()", "CRITICAL", "Code Injection",
            "\\beval\\s*\\(",
            "CWE-95", "N'utilisez jamais eval(). Utilisez JSON.parse()",
            "eval_injection"),
        rule("JS005", "Command Injection", "CRITICAL", "Injection",
            "exec\\s*\\(\\s*`[^`]*\\$\\{|exec\\s*\\(\\s*[\"'].*?\\+",
            "CWE-78", "Utilisez execFile() avec un tableau d'arguments",
            "command_injection"),
        rule("JS006", "Insecure Random", "MEDIUM", "Cryptography",
            "Math\\.random\\s*\\(",
            "CWE-338", "Utilisez crypto.randomBytes() ou crypto.getRandomValues()",
            "weak_random"),
        rule("JS007", "Path Traversal", "HIGH", "File Access",
            "(sendFile|readFile|readFileSync)\\s*\\(.*\\+.*\\)",
            "CWE-22", "Utilisez path.resolve() et vérifiez le répertoire de base",
            "path_traversal"),
        rule("JS008", "Prototype Pollution", "HIGH", "Object Injection",
            "for\\s*\\(\\s*(let|var|const)\\s+\\w+\\s+in\\s+\\w+\\s*\\)",
            "CWE-1321", "Utilisez hasOwnProperty() ou Object.hasOwn()",
            "prototype_pollution")
    );

    // ── ANALYZE ───────────────────────────────────────────────────
    public List<Vulnerability> analyzeCode(String code, String language) {
        List<Map<String, String>> rules = switch (language.toLowerCase()) {
            case "java" -> JAVA_RULES;
            case "python" -> PYTHON_RULES;
            case "javascript", "js", "typescript", "ts" -> JS_RULES;
            default -> JAVA_RULES;
        };

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String[] lines = code.split("\n");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            for (Map<String, String> rule : rules) {
                Pattern pattern = Pattern.compile(rule.get("pattern"), Pattern.CASE_INSENSITIVE);
                if (pattern.matcher(line).find()) {
                    Vulnerability vuln = Vulnerability.builder()
                        .ruleId(rule.get("id"))
                        .name(rule.get("name"))
                        .severity(rule.get("severity"))
                        .category(rule.get("category"))
                        .cwe(rule.get("cwe"))
                        .description(rule.get("description"))
                        .lineNumber(i + 1)
                        .lineContent(line.trim().length() > 200 ? line.trim().substring(0, 200) : line.trim())
                        .recommendation(rule.get("recommendation"))
                        .testTemplate(rule.get("testTemplate"))
                        .build();
                    vulnerabilities.add(vuln);
                }
            }
        }
        return vulnerabilities;
    }

    public String detectLanguage(String filename) {
        if (filename == null) return "java";
        String lower = filename.toLowerCase();
        if (lower.endsWith(".java")) return "java";
        if (lower.endsWith(".py")) return "python";
        if (lower.endsWith(".js") || lower.endsWith(".ts")) return "javascript";
        return "java";
    }

    private static Map<String, String> rule(String id, String name, String severity,
            String category, String pattern, String cwe, String recommendation, String testTemplate) {
        Map<String, String> map = new HashMap<>();
        map.put("id", id);
        map.put("name", name);
        map.put("severity", severity);
        map.put("category", category);
        map.put("pattern", pattern);
        map.put("cwe", cwe);
        map.put("description", name + " détecté — " + recommendation);
        map.put("recommendation", recommendation);
        map.put("testTemplate", testTemplate);
        return map;
    }
}
