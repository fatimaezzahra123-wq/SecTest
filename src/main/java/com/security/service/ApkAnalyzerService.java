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
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.MASTER_CLEAR"
        });
        DANGEROUS_PERMISSIONS.put("HIGH", new String[]{
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.USE_BIOMETRIC",
            "android.permission.USE_FINGERPRINT"
        });
        DANGEROUS_PERMISSIONS.put("MEDIUM", new String[]{
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.BLUETOOTH",
            "android.permission.NFC",
            "android.permission.VIBRATE",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.WAKE_LOCK",
            "android.permission.FOREGROUND_SERVICE"
        });
    }

    // ── DEX CODE PATTERNS ─────────────────────────────────────────
    private static final List<Map<String, String>> DEX_PATTERNS = List.of(
        Map.of("name", "Certificat SSL non vérifié", "severity", "CRITICAL",
               "pattern", "TrustAllCerts|checkServerTrusted[\\s\\S]{0,50}\\{\\s*\\}|ALLOW_ALL_HOSTNAME_VERIFIER",
               "cwe", "CWE-295", "category", "Insecure Communication",
               "recommendation", "Implémentez correctement SSL: utilisez le certificate pinning"),
        Map.of("name", "Cleartext Traffic autorisé", "severity", "CRITICAL",
               "pattern", "android:usesCleartextTraffic\\s*=\\s*\"true\"|cleartextTrafficPermitted\\s*=\\s*\"true\"",
               "cwe", "CWE-319", "category", "Insecure Communication",
               "recommendation", "Désactivez: android:usesCleartextTraffic=\"false\""),
        Map.of("name", "Mode Debug activé", "severity", "CRITICAL",
               "pattern", "android:debuggable\\s*=\\s*\"true\"",
               "cwe", "CWE-215", "category", "Configuration",
               "recommendation", "Désactivez: android:debuggable=\"false\" avant la production"),
        Map.of("name", "Backup activé", "severity", "HIGH",
               "pattern", "android:allowBackup\\s*=\\s*\"true\"",
               "cwe", "CWE-530", "category", "Configuration",
               "recommendation", "Désactivez: android:allowBackup=\"false\""),
        Map.of("name", "HTTP non sécurisé", "severity", "HIGH",
               "pattern", "http://(?!localhost|127\\.0\\.0\\.1|10\\.0\\.2\\.2)",
               "cwe", "CWE-319", "category", "Insecure Communication",
               "recommendation", "Utilisez HTTPS pour toutes les communications réseau"),
        Map.of("name", "Hardcoded API Key", "severity", "HIGH",
               "pattern", "(?i)(api_key|apikey|secret|password|token)\\s*=\\s*[\"'][^\"']{8,}[\"']",
               "cwe", "CWE-798", "category", "Secret Exposure",
               "recommendation", "Utilisez Android Keystore pour les secrets"),
        Map.of("name", "SharedPreferences non chiffré", "severity", "HIGH",
               "pattern", "getSharedPreferences|SharedPreferences\\.Editor",
               "cwe", "CWE-312", "category", "Insecure Storage",
               "recommendation", "Utilisez EncryptedSharedPreferences"),
        Map.of("name", "SQLite non chiffré", "severity", "HIGH",
               "pattern", "openOrCreateDatabase|SQLiteOpenHelper",
               "cwe", "CWE-312", "category", "Insecure Storage",
               "recommendation", "Utilisez SQLCipher pour chiffrer SQLite"),
        Map.of("name", "WebView JavaScript activé", "severity", "MEDIUM",
               "pattern", "setJavaScriptEnabled\\s*\\(\\s*true\\s*\\)",
               "cwe", "CWE-79", "category", "XSS",
               "recommendation", "Désactivez JavaScript si non nécessaire"),
        Map.of("name", "Log de données sensibles", "severity", "MEDIUM",
               "pattern", "Log\\.(d|e|i|v|w)\\s*\\(.*(?i)(password|token|secret|key)",
               "cwe", "CWE-532", "category", "Information Disclosure",
               "recommendation", "Ne jamais logger de données sensibles"),
        Map.of("name", "Stockage externe", "severity", "HIGH",
               "pattern", "getExternalStorage|Environment\\.getExternalStorageDirectory",
               "cwe", "CWE-312", "category", "Insecure Storage",
               "recommendation", "Utilisez le stockage interne: getFilesDir()")
    );

    // ── ANALYZE APK ───────────────────────────────────────────────
    public List<Vulnerability> analyzeApk(byte[] apkBytes, String fileName) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            // Sauvegarder l'APK temporairement
            Path tempApk = Files.createTempFile("apk_", ".apk");
            Files.write(tempApk, apkBytes);

            // Dossier de sortie APKTool
            Path outputDir = Files.createTempDirectory("apk_output_");

            // Chercher apktool.jar
            Path apktoolJar = extractApktool();

            boolean apktoolSuccess = false;
            if (apktoolJar != null) {
                apktoolSuccess = runApktool(apktoolJar, tempApk, outputDir);
            }

            if (apktoolSuccess) {
                // Analyser avec APKTool output (manifest XML propre)
                analyzeWithApktool(outputDir, vulnerabilities);
            } else {
                // Fallback: analyser le ZIP directement
                analyzeAsZip(tempApk, vulnerabilities);
            }

            // Nettoyer
            Files.deleteIfExists(tempApk);
            deleteDirectory(outputDir);

        } catch (Exception e) {
            vulnerabilities.add(Vulnerability.builder()
                .ruleId("APK-ERR")
                .name("Erreur d'analyse APK")
                .severity("INFO")
                .category("Analysis")
                .cwe("N/A")
                .description("Erreur: " + e.getMessage())
                .lineNumber(0)
                .lineContent("")
                .recommendation("Vérifiez que l'APK est valide")
                .testTemplate("apk_security")
                .build());
        }

        return vulnerabilities;
    }

    // ── Extraire APKTool depuis les resources ─────────────────────
    private Path extractApktool() {
        try {
            InputStream is = getClass().getResourceAsStream("/apktool.jar");
            if (is == null) return null;
            Path tempJar = Files.createTempFile("apktool_", ".jar");
            Files.copy(is, tempJar, StandardCopyOption.REPLACE_EXISTING);
            is.close();
            return tempJar;
        } catch (Exception e) {
            return null;
        }
    }

    // ── Lancer APKTool ────────────────────────────────────────────
    private boolean runApktool(Path apktoolJar, Path apkFile, Path outputDir) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                "java", "-jar", apktoolJar.toString(),
                "d", apkFile.toString(),
                "-o", outputDir.toString(),
                "-f", "--no-src"
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();
            boolean finished = process.waitFor(60, java.util.concurrent.TimeUnit.SECONDS);
            return finished && process.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    // ── Analyser avec APKTool output ──────────────────────────────
    private void analyzeWithApktool(Path outputDir, List<Vulnerability> vulnerabilities) throws Exception {
        // Lire AndroidManifest.xml (propre et lisible)
        Path manifestPath = outputDir.resolve("AndroidManifest.xml");
        if (Files.exists(manifestPath)) {
            String manifest = new String(Files.readAllBytes(manifestPath));
            analyzeManifest(manifest, vulnerabilities);
        }

        // Analyser les fichiers smali
        Path smaliDir = outputDir.resolve("smali");
        if (Files.exists(smaliDir)) {
            analyzeSmaliFiles(smaliDir, vulnerabilities);
        }

        // Analyser les fichiers res/xml
        Path resDir = outputDir.resolve("res");
        if (Files.exists(resDir)) {
            analyzeResFiles(resDir, vulnerabilities);
        }
    }

    // ── Analyser le manifest XML propre ──────────────────────────
    private void analyzeManifest(String manifest, List<Vulnerability> vulnerabilities) {
        Set<String> foundPermissions = new LinkedHashSet<>();
        Set<String> detectedPatterns = new HashSet<>();

        // Détecter permissions
        for (Map.Entry<String, String[]> permEntry : DANGEROUS_PERMISSIONS.entrySet()) {
            for (String perm : permEntry.getValue()) {
                if (manifest.contains(perm)) {
                    foundPermissions.add(permEntry.getKey() + ":" + perm);
                }
            }
        }

        // Ajouter vulnérabilités de permissions
        for (String permEntry : foundPermissions) {
            String[] parts = permEntry.split(":", 2);
            String severity = parts[0];
            String permission = parts[1];
            String shortName = permission.substring(permission.lastIndexOf('.') + 1);

            vulnerabilities.add(Vulnerability.builder()
                .ruleId("APK-PERM")
                .name("Permission dangereuse: " + shortName)
                .severity(severity)
                .category("Dangerous Permission")
                .cwe("CWE-250")
                .description("L'application demande: " + permission)
                .lineNumber(0)
                .lineContent("uses-permission: " + permission)
                .recommendation("Vérifiez si " + shortName + " est strictement nécessaire.")
                .testTemplate("dangerous_permission")
                .build());
        }

        // Détecter exported components
        detectExportedComponentsFromXml(manifest, vulnerabilities);

        // Appliquer les patterns sur le manifest
        String[] lines = manifest.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            for (Map<String, String> patternMap : DEX_PATTERNS) {
                String patternName = patternMap.get("name");
                if (detectedPatterns.contains(patternName)) continue;
                Pattern p = Pattern.compile(patternMap.get("pattern"), Pattern.CASE_INSENSITIVE);
                if (p.matcher(line).find()) {
                    detectedPatterns.add(patternName);
                    addVulnerability(vulnerabilities, patternMap, i + 1, line);
                }
            }
        }
    }

    // ── Détecter exported components depuis XML propre ────────────
    private void detectExportedComponentsFromXml(String manifest, List<Vulnerability> vulnerabilities) {
        String[] lines = manifest.split("\n");
        String[] componentTypes = {"activity", "service", "receiver", "provider"};

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            for (String type : componentTypes) {
                if (line.startsWith("<" + type) && line.contains("android:exported=\"true\"")) {
                    // Vérifier absence de permission
                    boolean hasPermission = false;
                    for (int j = i; j < Math.min(i + 5, lines.length); j++) {
                        if (lines[j].contains("android:permission")) {
                            hasPermission = true;
                            break;
                        }
                    }
                    if (!hasPermission) {
                        // Extraire le nom
                        String name = extractNameFromLine(line);
                        vulnerabilities.add(Vulnerability.builder()
                            .ruleId("APK-EXPORT")
                            .name("Composant exporté sans permission: " + name)
                            .severity("CRITICAL")
                            .category("Exported Component")
                            .cwe("CWE-926")
                            .description("Le " + type + " '" + name + "' est accessible par toutes les apps")
                            .lineNumber(i + 1)
                            .lineContent(line.length() > 150 ? line.substring(0, 150) : line)
                            .recommendation("Ajoutez android:permission ou mettez android:exported=\"false\"")
                            .testTemplate("exported_component")
                            .build());
                    }
                }
            }
        }
    }

    // ── Analyser fichiers smali ───────────────────────────────────
    private void analyzeSmaliFiles(Path smaliDir, List<Vulnerability> vulnerabilities) throws Exception {
        Set<String> detectedPatterns = new HashSet<>();
        Files.walk(smaliDir)
            .filter(p -> p.toString().endsWith(".smali"))
            .limit(50) // Limiter pour les performances
            .forEach(smaliFile -> {
                try {
                    String content = new String(Files.readAllBytes(smaliFile));
                    String[] lines = content.split("\n");
                    for (int i = 0; i < lines.length; i++) {
                        String line = lines[i];
                        for (Map<String, String> patternMap : DEX_PATTERNS) {
                            String patternName = patternMap.get("name");
                            if (detectedPatterns.contains(patternName)) continue;
                            Pattern p = Pattern.compile(patternMap.get("pattern"), Pattern.CASE_INSENSITIVE);
                            if (p.matcher(line).find()) {
                                detectedPatterns.add(patternName);
                                addVulnerability(vulnerabilities, patternMap, i + 1, line);
                            }
                        }
                    }
                } catch (Exception ignored) {}
            });
    }

    // ── Analyser fichiers res ─────────────────────────────────────
    private void analyzeResFiles(Path resDir, List<Vulnerability> vulnerabilities) throws Exception {
        Set<String> detectedPatterns = new HashSet<>();
        Files.walk(resDir)
            .filter(p -> p.toString().endsWith(".xml"))
            .forEach(xmlFile -> {
                try {
                    String content = new String(Files.readAllBytes(xmlFile));
                    String[] lines = content.split("\n");
                    for (int i = 0; i < lines.length; i++) {
                        String line = lines[i];
                        for (Map<String, String> patternMap : DEX_PATTERNS) {
                            String patternName = patternMap.get("name");
                            if (detectedPatterns.contains(patternName)) continue;
                            Pattern p = Pattern.compile(patternMap.get("pattern"), Pattern.CASE_INSENSITIVE);
                            if (p.matcher(line).find()) {
                                detectedPatterns.add(patternName);
                                addVulnerability(vulnerabilities, patternMap, i + 1, line);
                            }
                        }
                    }
                } catch (Exception ignored) {}
            });
    }

    // ── Fallback: analyser comme ZIP ─────────────────────────────
    private void analyzeAsZip(Path tempApk, List<Vulnerability> vulnerabilities) {
        try {
            StringBuilder content = new StringBuilder();
            Set<String> foundPermissions = new LinkedHashSet<>();

            try (ZipInputStream zis = new ZipInputStream(new FileInputStream(tempApk.toFile()))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    String entryName = entry.getName();
                    if (entryName.equals("AndroidManifest.xml")) {
                        byte[] bytes = zis.readAllBytes();
                        String str = extractStringsFromBinary(bytes);
                        content.append(str).append("\n");
                        for (Map.Entry<String, String[]> permEntry : DANGEROUS_PERMISSIONS.entrySet()) {
                            for (String perm : permEntry.getValue()) {
                                if (str.contains(perm)) {
                                    foundPermissions.add(permEntry.getKey() + ":" + perm);
                                }
                            }
                        }
                    }
                }
            }

            for (String permEntry : foundPermissions) {
                String[] parts = permEntry.split(":", 2);
                String permission = parts[1];
                String shortName = permission.substring(permission.lastIndexOf('.') + 1);
                vulnerabilities.add(Vulnerability.builder()
                    .ruleId("APK-PERM")
                    .name("Permission dangereuse: " + shortName)
                    .severity(parts[0])
                    .category("Dangerous Permission")
                    .cwe("CWE-250")
                    .description("L'application demande: " + permission)
                    .lineNumber(0)
                    .lineContent("uses-permission: " + permission)
                    .recommendation("Vérifiez si cette permission est nécessaire.")
                    .testTemplate("dangerous_permission")
                    .build());
            }

            // Appliquer patterns sur le contenu
            String[] lines = content.toString().split("\n");
            Set<String> detected = new HashSet<>();
            for (int i = 0; i < lines.length; i++) {
                for (Map<String, String> patternMap : DEX_PATTERNS) {
                    String name = patternMap.get("name");
                    if (detected.contains(name)) continue;
                    Pattern p = Pattern.compile(patternMap.get("pattern"), Pattern.CASE_INSENSITIVE);
                    if (p.matcher(lines[i]).find()) {
                        detected.add(name);
                        addVulnerability(vulnerabilities, patternMap, i + 1, lines[i]);
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }
    }

    // ── Helpers ───────────────────────────────────────────────────
    private void addVulnerability(List<Vulnerability> vulns, Map<String, String> patternMap, int line, String lineContent) {
        vulns.add(Vulnerability.builder()
            .ruleId("APK-" + patternMap.get("cwe").replace("CWE-", ""))
            .name(patternMap.get("name"))
            .severity(patternMap.get("severity"))
            .category(patternMap.get("category"))
            .cwe(patternMap.get("cwe"))
            .description(patternMap.get("name") + " détecté dans l'APK")
            .lineNumber(line)
            .lineContent(lineContent.trim().length() > 150 ? lineContent.trim().substring(0, 150) : lineContent.trim())
            .recommendation(patternMap.get("recommendation"))
            .testTemplate("apk_security")
            .build());
    }

    private String extractNameFromLine(String line) {
        if (line.contains("android:name=\"")) {
            int start = line.indexOf("android:name=\"") + 14;
            int end = line.indexOf("\"", start);
            if (end > start) {
                String fullName = line.substring(start, end);
                return fullName.substring(fullName.lastIndexOf('.') + 1);
            }
        }
        return "UnknownComponent";
    }

    private String extractStringsFromBinary(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        StringBuilder current = new StringBuilder();
        for (byte b : bytes) {
            char c = (char) (b & 0xFF);
            if (c >= 32 && c < 127) {
                current.append(c);
            } else {
                
                if (current.length() >= 4) sb.append(current).append("\n");
                current = new StringBuilder();
            }
        }
        return sb.toString();
    }

    private void deleteDirectory(Path dir) {
        try {
            Files.walk(dir)
                .sorted(Comparator.reverseOrder())
                .forEach(p -> { try { Files.deleteIfExists(p); } catch (Exception ignored) {} });
        } catch (Exception ignored) {}
    }
}
