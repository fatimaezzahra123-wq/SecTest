package com.security.service;

import com.security.model.Vulnerability;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class TestGeneratorService {

    public String generateTests(List<Vulnerability> vulnerabilities, String language, String fileName) {
        StringBuilder sb = new StringBuilder();

        sb.append("// ============================================================\n");
        sb.append("// AUTO-GENERATED SECURITY TESTS\n");
        sb.append("// Généré par Security Regression Test Generator\n");
        sb.append("// Fichier analysé: ").append(fileName).append("\n");
        sb.append("// NE PAS MODIFIER MANUELLEMENT\n");
        sb.append("// ============================================================\n\n");

        if ("apk".equalsIgnoreCase(language)) {
            return generateApkTests(vulnerabilities, fileName, sb);
        }

        // Tests JUnit pour code source
        sb.append("import org.junit.jupiter.api.Test;\n");
        sb.append("import org.junit.jupiter.api.DisplayName;\n");
        sb.append("import static org.junit.jupiter.api.Assertions.*;\n");
        sb.append("import java.util.regex.*;\n");
        sb.append("import java.io.*;\n\n");
        sb.append("public class SecurityGeneratedTests {\n\n");

        if (vulnerabilities.isEmpty()) {
            sb.append("    @Test\n");
            sb.append("    @DisplayName(\"✅ No vulnerabilities detected\")\n");
            sb.append("    public void testCodeIsSecure() {\n");
            sb.append("        assertTrue(true, \"Code analysé: aucune vulnérabilité détectée\");\n");
            sb.append("    }\n");
        } else {
            for (int i = 0; i < vulnerabilities.size(); i++) {
                Vulnerability v = vulnerabilities.get(i);
                String methodName = sanitizeName(v.getName()) + "_" + (i + 1);

                sb.append("    @Test\n");
                sb.append("    @DisplayName(\"[").append(v.getSeverity()).append("] ")
                  .append(v.getName()).append(" — Ligne ").append(v.getLineNumber()).append("\")\n");
                sb.append("    public void test_").append(methodName).append("() {\n");
                sb.append("        // SECURITY TEST: ").append(v.getName()).append("\n");
                sb.append("        // CWE: ").append(v.getCwe()).append("\n");
                sb.append("        // Ligne: ").append(v.getLineNumber()).append("\n");
                sb.append("        // Recommandation: ").append(v.getRecommendation()).append("\n\n");

                switch (v.getTestTemplate()) {
                    case "hardcoded_secret" -> {
                        sb.append("        // Vérifie qu'aucun secret n'est hardcodé\n");
                        sb.append("        String sourceCode = readFile(\"").append(fileName).append("\");\n");
                        sb.append("        Pattern pattern = Pattern.compile(\n");
                        sb.append("            \"(?i)(password|secret|apikey|token)\\\\s*=\\\\s*\\\"[^\\\"]{4,}\\\"\"\n");
                        sb.append("        );\n");
                        sb.append("        assertFalse(pattern.matcher(sourceCode).find(),\n");
                        sb.append("            \"VULNERABILITY: Secret hardcodé détecté à la ligne ")
                          .append(v.getLineNumber()).append("\");\n");
                    }
                    case "weak_hash" -> {
                        sb.append("        String sourceCode = readFile(\"").append(fileName).append("\");\n");
                        sb.append("        assertFalse(sourceCode.contains(\"MD5\") || sourceCode.contains(\"SHA-1\"),\n");
                        sb.append("            \"VULNERABILITY: Algorithme de hash faible détecté à la ligne ")
                          .append(v.getLineNumber()).append("\");\n");
                    }
                    case "weak_random" -> {
                        sb.append("        String sourceCode = readFile(\"").append(fileName).append("\");\n");
                        sb.append("        assertFalse(sourceCode.contains(\"new Random()\") || sourceCode.contains(\"Math.random()\"),\n");
                        sb.append("            \"VULNERABILITY: Générateur aléatoire non sécurisé à la ligne ")
                          .append(v.getLineNumber()).append("\");\n");
                    }
                    case "sql_injection" -> {
                        sb.append("        // Test: payload SQL injection\n");
                        sb.append("        String[] sqlPayloads = {\n");
                        sb.append("            \"' OR '1'='1\",\n");
                        sb.append("            \"'; DROP TABLE users; --\",\n");
                        sb.append("            \"' UNION SELECT * FROM users --\"\n");
                        sb.append("        };\n");
                        sb.append("        // Vérification que le pattern dangereux est présent\n");
                        sb.append("        String sourceCode = readFile(\"").append(fileName).append("\");\n");
                        sb.append("        assertFalse(sourceCode.contains(\"+\") && sourceCode.toLowerCase().contains(\"select\"),\n");
                        sb.append("            \"VULNERABILITY: Concaténation SQL détectée à la ligne ")
                          .append(v.getLineNumber()).append("\");\n");
                    }
                    default -> {
                        sb.append("        // Pattern dangereux détecté à la ligne ").append(v.getLineNumber()).append("\n");
                        sb.append("        // Revue manuelle requise pour: ").append(v.getName()).append("\n");
                        sb.append("        String sourceCode = readFile(\"").append(fileName).append("\");\n");
                        sb.append("        assertNotNull(sourceCode, \"Fichier source accessible\");\n");
                        sb.append("        // TODO: Corriger le pattern à la ligne ").append(v.getLineNumber()).append("\n");
                        sb.append("        System.out.println(\"[WARN] Vulnérabilité détectée: ").append(v.getName())
                          .append(" à la ligne ").append(v.getLineNumber()).append("\");\n");
                    }
                }

                sb.append("    }\n\n");
            }
        }

        // Helper method
        sb.append("    private String readFile(String path) {\n");
        sb.append("        try {\n");
        sb.append("            return new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path)));\n");
        sb.append("        } catch (Exception e) {\n");
        sb.append("            return \"\";\n");
        sb.append("        }\n");
        sb.append("    }\n");
        sb.append("}\n");

        return sb.toString();
    }

    private String generateApkTests(List<Vulnerability> vulnerabilities, String fileName, StringBuilder sb) {
        sb.append("import org.junit.jupiter.api.Test;\n");
        sb.append("import org.junit.jupiter.api.DisplayName;\n");
        sb.append("import static org.junit.jupiter.api.Assertions.*;\n\n");
        sb.append("public class ApkSecurityGeneratedTests {\n\n");

        if (vulnerabilities.isEmpty()) {
            sb.append("    @Test\n");
            sb.append("    @DisplayName(\"✅ APK — Aucune vulnérabilité détectée\")\n");
            sb.append("    public void testApkIsSecure() {\n");
            sb.append("        assertTrue(true, \"APK analysé: aucune vulnérabilité détectée\");\n");
            sb.append("    }\n");
        } else {
            for (int i = 0; i < vulnerabilities.size(); i++) {
                Vulnerability v = vulnerabilities.get(i);
                String methodName = sanitizeName(v.getName()) + "_" + (i + 1);

                sb.append("    @Test\n");
                sb.append("    @DisplayName(\"[").append(v.getSeverity()).append("] APK: ")
                  .append(v.getName()).append("\")\n");
                sb.append("    public void test_apk_").append(methodName).append("() {\n");
                sb.append("        // APK SECURITY TEST: ").append(v.getName()).append("\n");
                sb.append("        // CWE: ").append(v.getCwe()).append("\n");
                sb.append("        // Recommandation: ").append(v.getRecommendation()).append("\n\n");
                sb.append("        // Ce test documente la vulnérabilité détectée dans l'APK\n");
                sb.append("        // Code détecté: ").append(v.getLineContent().replace("\"", "'")).append("\n");
                sb.append("        System.out.println(\"[").append(v.getSeverity()).append("] ")
                  .append(v.getName()).append(" — ").append(v.getRecommendation()).append("\");\n");
                sb.append("        assertNotNull(\"").append(v.getCwe()).append("\", \"CWE référencé\");\n");
                sb.append("    }\n\n");
            }
        }

        sb.append("}\n");
        return sb.toString();
    }

    private String sanitizeName(String name) {
        return name.toLowerCase()
            .replaceAll("[^a-z0-9]", "_")
            .replaceAll("_+", "_")
            .replaceAll("^_|_$", "");
    }
}
