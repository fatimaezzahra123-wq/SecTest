package com.security.service;

import com.security.model.Vulnerability;
import org.springframework.stereotype.Service;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.*;

@Service
public class ApkAnalyzerService {

    // ── DANGEROUS PERMISSIONS ─────────────────────────────────────
    private static final Map<String, String[]> DANGEROUS_PERMISSIONS = new LinkedHashMap<>();
    static {
        DANGEROUS_PERMISSIONS.put("CRITICAL", new String[]{
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.CALL_PHONE",
            "android.permission.PROCESS_OUTGOING_CALLS"
        });
        DANGEROUS_PERMISSIONS.put("HIGH", new String[]{
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE"
        });
        DANGEROUS_PERMISSIONS.put("MEDIUM", new String[]{
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.BLUETOOTH",
            "android.permission.NFC",
            "android.permission.VIBRATE"
        });
    }

    // ── DEX CODE PATTERNS ─────────────────────────────────────────
    private static final List<Map<String, String>> DEX_PATTERNS = List.of(
        Map.of("name", "Hardcoded API Key", "severity", "HIGH",
               "pattern", "(?i)(api_key|apikey|secret|password|token)\\s*=\\s*[\"'][^\"']{8,}[\"']",
               "cwe", "CWE-798", "category", "Secret Exposure",
               "recommendation", "Utilisez Android Keystore ou des variables d'environnement"),
        Map.of("name", "HTTP non sécurisé", "severity", "HIGH",
               "pattern", "http://(?!localhost|127\\.0\\.0\\.1)",
               "cwe", "CWE-319", "category", "Insecure Communication",
               "recommendation", "Utilisez HTTPS pour toutes les communications réseau"),
        Map.of("name", "Stockage non sécurisé SharedPreferences", "severity", "HIGH",
               "pattern", "getSharedPreferences|SharedPreferences\\.Editor",
               "cwe", "CWE-312", "category", "Insecure Storage",
               "recommendation", "Utilisez EncryptedSharedPreferences pour les données sensibles"),
        Map.of("name", "WebView JavaScript activé", "severity", "MEDIUM",
               "pattern", "setJavaScriptEnabled\\s*\\(\\s*true\\s*\\)",
               "cwe", "CWE-79", "category", "XSS",
               "recommendation", "Désactivez JavaScript si non nécessaire ou validez les URLs"),
        Map.of("name", "Log de données sensibles", "severity", "MEDIUM",
               "pattern", "Log\\.(d|e|i|v|w)\\s*\\(.*(?i)(password|token|secret|key)",
               "cwe", "CWE-532", "category", "Information Disclosure",
               "recommendation", "Ne jamais logger de données sensibles en production"),
        Map.of("name", "SQLite non chiffré", "severity", "HIGH",
               "pattern", "openOrCreateDatabase|SQLiteOpenHelper",
               "cwe", "CWE-312", "category", "Insecure Storage",
               "recommendation", "Utilisez SQLCipher pour chiffrer la base de données SQLite"),
        Map.of("name", "Certificat SSL non vérifié", "severity", "CRITICAL",
               "pattern", "TrustAllCerts|X509TrustManager|checkServerTrusted.*\\{\\s*\\}",
               "cwe", "CWE-295", "category", "Insecure Communication",
               "recommendation", "Implémentez correctement la validation des certificats SSL"),
        Map.of("name", "Mode Debug activé", "severity", "MEDIUM",
               "pattern", "android:debuggable\\s*=\\s*\"true\"",
               "cwe", "CWE-215", "category", "Configuration",
               "recommendation", "Désactivez le mode debug en production: android:debuggable=\"false\""),
        Map.of("name", "Backup activé", "severity", "LOW",
               "pattern", "android:allowBackup\\s*=\\s*\"true\"",
               "cwe", "CWE-530", "category", "Configuration",
               "recommendation", "Désactivez le backup: android:allowBackup=\"false\""),
        Map.of("name", "Intent implicite dangereux", "severity", "MEDIUM",
               "pattern", "new Intent\\(\\)|Intent\\.ACTION",
               "cwe", "CWE-927", "category", "IPC Security",
               "recommendation", "Utilisez des intents explicites avec le nom complet du composant")
    );

    // ── ANALYZE APK ───────────────────────────────────────────────
    public List<Vulnerability> analyzeApk(byte[] apkBytes, String fileName) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            // Lire l'APK comme ZIP
            Path tempApk = Files.createTempFile("apk_", ".apk");
            Files.write(tempApk, apkBytes);

            StringBuilder apkContent = new StringBuilder();
            Set<String> foundPermissions = new LinkedHashSet<>();

            try (ZipInputStream zis = new ZipInputStream(new FileInputStream(tempApk.toFile()))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    String entryName = entry.getName();

                    // Lire AndroidManifest.xml (binaire → chercher les strings)
                    if (entryName.equals("AndroidManifest.xml")) {
                        byte[] manifestBytes = zis.readAllBytes();
                        String manifestStr = extractStringsFromBinary(manifestBytes);
                        apkContent.append(manifestStr).append("\n");

                        // Détecter les permissions
                        for (Map.Entry<String, String[]> permEntry : DANGEROUS_PERMISSIONS.entrySet()) {
                            for (String perm : permEntry.getValue()) {
                                if (manifestStr.contains(perm)) {
                                    foundPermissions.add(permEntry.getKey() + ":" + perm);
                                }
                            }
                        }
                    }

                    // Lire les fichiers .smali, .xml, .properties, .java
                    if (entryName.endsWith(".smali") || entryName.endsWith(".xml")
                            || entryName.endsWith(".properties") || entryName.endsWith(".java")
                            || entryName.endsWith(".kt")) {
                        try {
                            byte[] content = zis.readAllBytes();
                            apkContent.append(new String(content)).append("\n");
                        } catch (Exception ignored) {}
                    }
                }
            }

            Files.deleteIfExists(tempApk);

            // Analyser les permissions trouvées
            for (String permEntry : foundPermissions) {
                String[] parts = permEntry.split(":", 2);
                String severity = parts[0];
                String permission = parts[1];

                vulnerabilities.add(Vulnerability.builder()
                    .ruleId("APK-PERM")
                    .name("Permission dangereuse: " + permission.substring(permission.lastIndexOf('.') + 1))
                    .severity(severity)
                    .category("Dangerous Permission")
                    .cwe("CWE-250")
                    .description("L'application demande la permission: " + permission)
                    .lineNumber(0)
                    .lineContent("uses-permission: " + permission)
                    .recommendation("Vérifiez si cette permission est strictement nécessaire. "
                        + "Expliquez à l'utilisateur pourquoi elle est requise.")
                    .testTemplate("dangerous_permission")
                    .build());
            }

            // Analyser le contenu avec les patterns
            String content = apkContent.toString();
            String[] lines = content.split("\n");

            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                for (Map<String, String> pattern : DEX_PATTERNS) {
                    Pattern p = Pattern.compile(pattern.get("pattern"), Pattern.CASE_INSENSITIVE);
                    if (p.matcher(line).find()) {
                        // Éviter les doublons
                        boolean duplicate = vulnerabilities.stream()
                            .anyMatch(v -> v.getName().equals(pattern.get("name")));
                        if (!duplicate) {
                            vulnerabilities.add(Vulnerability.builder()
                                .ruleId("APK-" + pattern.get("cwe").replace("CWE-", ""))
                                .name(pattern.get("name"))
                                .severity(pattern.get("severity"))
                                .category(pattern.get("category"))
                                .cwe(pattern.get("cwe"))
                                .description(pattern.get("name") + " détecté dans l'APK")
                                .lineNumber(i + 1)
                                .lineContent(line.trim().length() > 150 ? line.trim().substring(0, 150) : line.trim())
                                .recommendation(pattern.get("recommendation"))
                                .testTemplate("apk_security")
                                .build());
                        }
                    }
                }
            }

        } catch (Exception e) {
            // Si l'APK ne peut pas être lu comme ZIP valide
            vulnerabilities.add(Vulnerability.builder()
                .ruleId("APK-ERR")
                .name("Analyse partielle — APK non standard")
                .severity("INFO")
                .category("Analysis")
                .cwe("N/A")
                .description("L'APK a été partiellement analysé. " + e.getMessage())
                .lineNumber(0)
                .lineContent("")
                .recommendation("Utilisez un APK valide signé pour une analyse complète")
                .testTemplate("apk_security")
                .build());
        }

        return vulnerabilities;
    }

    // Extraire les strings lisibles depuis un binaire
    private String extractStringsFromBinary(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        StringBuilder current = new StringBuilder();
        for (byte b : bytes) {
            char c = (char) (b & 0xFF);
            if (c >= 32 && c < 127) {
                current.append(c);
            } else {
                if (current.length() >= 4) {
                    sb.append(current).append("\n");
                }
                current = new StringBuilder();
            }
        }
        return sb.toString();
    }
}
