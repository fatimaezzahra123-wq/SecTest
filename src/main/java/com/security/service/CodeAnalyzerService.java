package com.security.service;

import com.security.model.Vulnerability;
import org.springframework.stereotype.Service;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class CodeAnalyzerService {

    // ── JAVA RULES ────────────────────────────────────────────────
    private static final List<Map<String, String>> JAVA_RULES = List.of(

        // CRITICAL
        rule("JV001", "SQL Injection", "CRITICAL", "Injection",
            ".*\\.(execute|executeQuery|executeUpdate)\\s*\\(.*\\+.*\\)|" +
            ".*createQuery\\s*\\(.*\\+.*\\)|" +
            ".*createNativeQuery\\s*\\(.*\\+.*\\)|" +
            "\"\\s*SELECT.*WHERE.*\"\\s*\\+|" +
            "\"\\s*INSERT.*VALUES.*\"\\s*\\+|" +
            "\"\\s*UPDATE.*SET.*\"\\s*\\+|" +
            "\"\\s*DELETE.*FROM.*\"\\s*\\+",
            "CWE-89", "Utilisez PreparedStatement: pstmt.setString(1, userInput)",
            "sql_injection"),

        rule("JV002", "Command Injection", "CRITICAL", "Injection",
            "Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(|" +
            "new\\s+ProcessBuilder\\s*\\(|" +
            "ProcessBuilder.*add\\s*\\(.*\\+|" +
            "Runtime\\.exec\\s*\\(",
            "CWE-78", "N'utilisez jamais de données utilisateur dans exec(). Utilisez une liste d'arguments.",
            "command_injection"),

        rule("JV003", "XXE Injection", "CRITICAL", "Injection",
            "DocumentBuilderFactory\\.newInstance\\(\\)|" +
            "SAXParserFactory\\.newInstance\\(\\)|" +
            "XMLInputFactory\\.newInstance\\(\\)|" +
            "TransformerFactory\\.newInstance\\(\\)",
            "CWE-611", "Désactivez les entités: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
            "xxe"),

        rule("JV004", "Insecure Deserialization", "CRITICAL", "Deserialization",
            "new\\s+ObjectInputStream\\s*\\(|" +
            "\\.readObject\\s*\\(\\)|" +
            "XStream\\.fromXML\\s*\\(|" +
            "SerializationUtils\\.deserialize\\s*\\(",
            "CWE-502", "N'utilisez jamais readObject() sur des données non fiables. Utilisez JSON.",
            "insecure_deserialization"),

        rule("JV005", "Dangerous eval/OGNL", "CRITICAL", "Code Injection",
            "Ognl\\.getValue\\s*\\(|" +
            "ScriptEngine.*eval\\s*\\(|" +
            "GroovyShell.*evaluate\\s*\\(",
            "CWE-94", "N'évaluez jamais de code dynamique provenant de l'utilisateur.",
            "code_injection"),

        // HIGH
        rule("JV006", "Hardcoded Password", "HIGH", "Secret Exposure",
            "(?i)(password|passwd|pwd)\\s*=\\s*\"[^\"]{3,}\"|" +
            "(?i)(password|passwd|pwd)\\s*=\\s*'[^']{3,}'",
            "CWE-798", "Utilisez System.getenv(\"DB_PASSWORD\") ou un vault de secrets.",
            "hardcoded_password"),

        rule("JV007", "Hardcoded API Key/Token", "HIGH", "Secret Exposure",
            "(?i)(api_?key|apikey|secret|token|access_?key|auth)\\s*=\\s*\"[^\"]{6,}\"|" +
            "(?i)(api_?key|apikey|secret|token|access_?key|auth)\\s*=\\s*'[^']{6,}'",
            "CWE-798", "Utilisez System.getenv(\"API_KEY\") ou un gestionnaire de secrets.",
            "hardcoded_secret"),

        rule("JV008", "Weak Hash MD5", "HIGH", "Cryptography",
            "MessageDigest\\.getInstance\\s*\\(\\s*\"MD5\"\\s*\\)|" +
            "DigestUtils\\.md5\\s*\\(|" +
            "getMD5\\s*\\(",
            "CWE-328", "Utilisez SHA-256 ou bcrypt: MessageDigest.getInstance(\"SHA-256\")",
            "weak_hash_md5"),

        rule("JV009", "Weak Hash SHA1", "HIGH", "Cryptography",
            "MessageDigest\\.getInstance\\s*\\(\\s*\"SHA-?1\"\\s*\\)|" +
            "DigestUtils\\.sha1\\s*\\(",
            "CWE-328", "Utilisez SHA-256 minimum: MessageDigest.getInstance(\"SHA-256\")",
            "weak_hash_sha1"),

        rule("JV010", "Path Traversal", "HIGH", "File Access",
            "new\\s+File\\s*\\(.*\\+.*\\)|" +
            "Paths\\.get\\s*\\(.*\\+.*\\)|" +
            "new\\s+FileInputStream\\s*\\(.*\\+.*\\)|" +
            "new\\s+FileOutputStream\\s*\\(.*\\+.*\\)",
            "CWE-22", "Validez: path.normalize().startsWith(basePath)",
            "path_traversal"),

        rule("JV011", "XSS Output", "HIGH", "XSS",
            "response\\.getWriter\\(\\).*print.*getParameter|" +
            "PrintWriter.*print.*getParameter|" +
            "out\\.print.*request\\.getParameter",
            "CWE-79", "Encodez: ESAPI.encoder().encodeForHTML(userInput)",
            "xss"),

        rule("JV012", "Weak SSL/TLS", "HIGH", "Cryptography",
            "SSLContext\\.getInstance\\s*\\(\\s*\"SSL\"|" +
            "SSLContext\\.getInstance\\s*\\(\\s*\"TLS(v1|v1\\.1|10|11)?\"|" +
            "setEnabledProtocols.*SSLv|" +
            "TrustAllCerts|X509TrustManager.*checkServerTrusted.*\\{\\s*\\}",
            "CWE-326", "Utilisez TLS 1.3: SSLContext.getInstance(\"TLSv1.3\")",
            "weak_tls"),

        rule("JV013", "Open Redirect", "HIGH", "Redirect",
            "response\\.sendRedirect\\s*\\(.*getParameter|" +
            "ModelAndView.*redirect.*getParameter|" +
            "RedirectView.*getParameter",
            "CWE-601", "Validez l'URL de redirection avec une liste blanche.",
            "open_redirect"),

        // MEDIUM
        rule("JV014", "Insecure Random", "MEDIUM", "Cryptography",
            "\\bnew\\s+Random\\s*\\(\\)|" +
            "\\bMath\\.random\\s*\\(",
            "CWE-338", "Utilisez SecureRandom: new SecureRandom()",
            "weak_random"),

        rule("JV015", "Log Injection", "MEDIUM", "Injection",
            "log\\.(info|debug|warn|error)\\s*\\(.*getParameter|" +
            "logger\\.(info|debug|warn|error)\\s*\\(.*getParameter|" +
            "System\\.out\\.println\\s*\\(.*getParameter",
            "CWE-117", "Nettoyez les entrées avant de les logger: input.replaceAll(\"[\\r\\n]\", \"\")",
            "log_injection"),

        rule("JV016", "Hardcoded IP Address", "MEDIUM", "Configuration",
            "\"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\"",
            "CWE-1121", "Utilisez des variables de configuration externes.",
            "hardcoded_ip"),

        rule("JV017", "Empty Catch Block", "MEDIUM", "Error Handling",
            "catch\\s*\\([^)]+\\)\\s*\\{\\s*\\}|" +
            "catch\\s*\\([^)]+\\)\\s*\\{\\s*//.*\\}",
            "CWE-390", "Loggez ou traitez toujours les exceptions.",
            "empty_catch"),

        rule("JV018", "Null Pointer Risk", "MEDIUM", "Error Handling",
            "\\.getParameter\\s*\\(.*\\)\\.(length|charAt|substring|indexOf)|" +
            "request\\.getParameter.*\\.equals\\s*\\(",
            "CWE-476", "Vérifiez null avant utilisation: if (param != null && !param.isEmpty())",
            "null_pointer"),

        // LOW
        rule("JV019", "printStackTrace", "LOW", "Information Disclosure",
            "\\.printStackTrace\\s*\\(\\)",
            "CWE-209", "Utilisez un logger: logger.error(\"Erreur\", e)",
            "stack_trace"),

        rule("JV020", "Commented Credentials", "LOW", "Secret Exposure",
            "(?i)//.*?(password|passwd|secret|apikey)\\s*[=:]\\s*\\S+",
            "CWE-615", "Supprimez les credentials commentés du code source.",
            "commented_credentials")
    );

    // ── PYTHON RULES ──────────────────────────────────────────────
    private static final List<Map<String, String>> PYTHON_RULES = List.of(

        rule("PY001", "SQL Injection", "CRITICAL", "Injection",
            "execute\\s*\\(\\s*[\"'].*?%\\s*\\w|" +
            "execute\\s*\\(\\s*[\"'].*?\\+|" +
            "execute\\s*\\(\\s*f[\"']|" +
            "executemany\\s*\\(.*\\+",
            "CWE-89", "Utilisez: cursor.execute('SELECT * FROM t WHERE id=%s', (user_id,))",
            "sql_injection"),

        rule("PY002", "Command Injection", "CRITICAL", "Injection",
            "os\\.system\\s*\\(|" +
            "subprocess\\.(run|call|Popen|check_output).*shell\\s*=\\s*True|" +
            "commands\\.getoutput\\s*\\(|" +
            "popen\\s*\\(",
            "CWE-78", "Utilisez shell=False: subprocess.run(['ping', host], shell=False)",
            "command_injection"),

        rule("PY003", "Insecure Deserialization", "CRITICAL", "Deserialization",
            "pickle\\.(loads|load|Unpickler)\\s*\\(|" +
            "yaml\\.load\\s*\\((?!.*Loader)|" +
            "marshal\\.loads\\s*\\(",
            "CWE-502", "Utilisez yaml.safe_load() ou json.loads() à la place.",
            "insecure_deserialization"),

        rule("PY004", "Hardcoded Password", "HIGH", "Secret Exposure",
            "(?i)(password|passwd|pwd)\\s*=\\s*[\"'][^\"']{3,}[\"']",
            "CWE-798", "Utilisez os.environ.get('PASSWORD')",
            "hardcoded_password"),

        rule("PY005", "Hardcoded Secret", "HIGH", "Secret Exposure",
            "(?i)(api_?key|secret|token|access_?key)\\s*=\\s*[\"'][^\"']{6,}[\"']",
            "CWE-798", "Utilisez os.environ.get('API_KEY') ou python-dotenv",
            "hardcoded_secret"),

        rule("PY006", "Weak Hash", "HIGH", "Cryptography",
            "hashlib\\.(md5|sha1)\\s*\\(|" +
            "(?i)MD5\\s*\\(|" +
            "crypt\\.crypt\\s*\\(",
            "CWE-328", "Utilisez hashlib.sha256() ou bcrypt",
            "weak_hash"),

        rule("PY007", "Path Traversal", "HIGH", "File Access",
            "open\\s*\\(.*\\+.*[\"']|" +
            "open\\s*\\(.*request\\.(args|form|json)|" +
            "os\\.path\\.join\\s*\\(.*request",
            "CWE-22", "Validez: os.path.abspath(path).startswith(base_dir)",
            "path_traversal"),

        rule("PY008", "Debug Mode", "HIGH", "Configuration",
            "app\\.run\\s*\\(.*debug\\s*=\\s*True|" +
            "DEBUG\\s*=\\s*True",
            "CWE-94", "Désactivez le mode debug en production: DEBUG=False",
            "debug_mode"),

        rule("PY009", "XSS", "HIGH", "XSS",
            "render_template_string\\s*\\(.*request|" +
            "Markup\\s*\\(.*request|" +
            "f[\"']<.*\\{.*request",
            "CWE-79", "Utilisez Jinja2 avec auto-échappement activé.",
            "xss"),

        rule("PY010", "Insecure Random", "MEDIUM", "Cryptography",
            "\\brandom\\.(randint|random|choice|shuffle|sample)\\s*\\(",
            "CWE-338", "Utilisez secrets.token_hex() pour les tokens de sécurité",
            "weak_random"),

        rule("PY011", "SQL avec string format", "CRITICAL", "Injection",
            "execute\\s*\\(.*%\\s*\\(|" +
            "execute\\s*\\(.*\\.format\\s*\\(",
            "CWE-89", "N'utilisez jamais format() dans les requêtes SQL.",
            "sql_format_injection"),

        rule("PY012", "Assert Security Check", "MEDIUM", "Logic Flaw",
            "assert\\s+\\w.*==.*True|" +
            "assert\\s+is_admin|" +
            "assert\\s+authenticated",
            "CWE-617", "N'utilisez pas assert pour les vérifications de sécurité (désactivé avec -O).",
            "assert_security")
    );

    // ── JAVASCRIPT RULES ──────────────────────────────────────────
    private static final List<Map<String, String>> JS_RULES = List.of(

        rule("JS001", "SQL Injection", "CRITICAL", "Injection",
            "[\"']\\s*SELECT.*WHERE.*[\"']\\s*\\+\\s*\\w+|" +
            "`SELECT.*\\$\\{|" +
            "[\"']\\s*INSERT.*VALUES.*[\"']\\s*\\+|" +
            "`INSERT.*\\$\\{|" +
            "[\"']\\s*DELETE.*FROM.*[\"']\\s*\\+",
            "CWE-89", "Utilisez des requêtes paramétrées ou un ORM comme Sequelize.",
            "sql_injection"),

        rule("JS002", "eval() Dangerous", "CRITICAL", "Code Injection",
            "\\beval\\s*\\(|" +
            "new\\s+Function\\s*\\(.*\\+|" +
            "setTimeout\\s*\\(\\s*[\"']|" +
            "setInterval\\s*\\(\\s*[\"']",
            "CWE-95", "N'utilisez jamais eval(). Utilisez JSON.parse() à la place.",
            "eval_injection"),

        rule("JS003", "Command Injection", "CRITICAL", "Injection",
            "exec\\s*\\(\\s*`[^`]*\\$\\{|" +
            "exec\\s*\\(\\s*[\"'].*?\\+|" +
            "spawn\\s*\\(.*shell.*true|" +
            "child_process.*exec\\s*\\(.*\\+",
            "CWE-78", "Utilisez execFile() avec un tableau d'arguments.",
            "command_injection"),

        rule("JS004", "Hardcoded Password", "HIGH", "Secret Exposure",
            "(?i)(password|passwd|pwd)\\s*[=:]\\s*[\"'][^\"']{3,}[\"']",
            "CWE-798", "Utilisez process.env.PASSWORD",
            "hardcoded_password"),

        rule("JS005", "Hardcoded Secret", "HIGH", "Secret Exposure",
            "(?i)(api_?key|apikey|secret|token|access_?key)\\s*[=:]\\s*[\"'][^\"']{6,}[\"']",
            "CWE-798", "Utilisez process.env.API_KEY",
            "hardcoded_secret"),

        rule("JS006", "XSS innerHTML", "HIGH", "XSS",
            "(innerHTML|outerHTML)\\s*=.*req\\.(query|body|params)|" +
            "(innerHTML|outerHTML)\\s*\\+=|" +
            "document\\.write\\s*\\(.*req\\.|" +
            "\\$\\(.*\\)\\.html\\s*\\(.*req\\.",
            "CWE-79", "Utilisez textContent ou sanitisez avec DOMPurify.",
            "xss_innerhtml"),

        rule("JS007", "Path Traversal", "HIGH", "File Access",
            "fs\\.(readFile|writeFile|readFileSync)\\s*\\(.*\\+|" +
            "res\\.sendFile\\s*\\(.*\\+|" +
            "path\\.join\\s*\\(.*req\\.",
            "CWE-22", "Utilisez path.resolve() et vérifiez le répertoire de base.",
            "path_traversal"),

        rule("JS008", "NoSQL Injection", "CRITICAL", "Injection",
            "\\$where\\s*:|" +
            "\\$regex.*req\\.|" +
            "find\\s*\\(\\s*req\\.(body|query|params)\\s*\\)",
            "CWE-89", "Validez et sanitisez les requêtes MongoDB.",
            "nosql_injection"),

        rule("JS009", "Insecure JWT", "HIGH", "Authentication",
            "jwt\\.sign\\s*\\(.*algorithm.*none|" +
            "jwt\\.verify\\s*\\(.*\\{\\s*algorithms.*none|" +
            "verify\\s*\\(.*false\\s*\\)",
            "CWE-347", "N'utilisez jamais l'algorithme 'none' pour JWT.",
            "insecure_jwt"),

        rule("JS010", "Insecure Random", "MEDIUM", "Cryptography",
            "Math\\.random\\s*\\(",
            "CWE-338", "Utilisez crypto.randomBytes() pour la sécurité.",
            "weak_random"),

        rule("JS011", "Prototype Pollution", "HIGH", "Object Injection",
            "__proto__\\s*\\[|" +
            "constructor\\s*\\[.*prototype|" +
            "Object\\.assign\\s*\\(\\s*\\{\\}.*req\\.",
            "CWE-1321", "Utilisez Object.create(null) ou validez les clés.",
            "prototype_pollution"),

        rule("JS012", "SSRF", "HIGH", "SSRF",
            "axios\\.(get|post)\\s*\\(.*req\\.(query|body|params)|" +
            "fetch\\s*\\(.*req\\.(query|body|params)|" +
            "http\\.get\\s*\\(.*req\\.",
            "CWE-918", "Validez les URLs avec une liste blanche de domaines autorisés.",
            "ssrf"),

        rule("JS013", "Hardcoded JWT Secret", "CRITICAL", "Secret Exposure",
            "jwt\\.sign\\s*\\(.*[\"'][a-zA-Z0-9]{8,}[\"']|" +
            "secret\\s*:\\s*[\"'][a-zA-Z0-9]{8,}[\"']",
            "CWE-798", "Utilisez process.env.JWT_SECRET",
            "hardcoded_jwt_secret"),

        rule("JS014", "Cookie sans Secure/HttpOnly", "MEDIUM", "Session",
            "res\\.cookie\\s*\\((?!.*httpOnly)|" +
            "Set-Cookie.*(?!.*Secure)(?!.*HttpOnly)",
            "CWE-614", "Ajoutez: res.cookie('name', val, { httpOnly: true, secure: true })",
            "insecure_cookie")
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
        Set<String> detectedRules = new HashSet<>();

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String trimmed = line.trim();
            if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) {
                continue; // skip pure comment lines
            }
            for (Map<String, String> rule : rules) {
                String ruleKey = rule.get("id") + "_" + (i + 1);
                if (detectedRules.contains(ruleKey)) continue;

                Pattern pattern = Pattern.compile(rule.get("pattern"), Pattern.CASE_INSENSITIVE);
                if (pattern.matcher(line).find()) {
                    detectedRules.add(ruleKey);
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