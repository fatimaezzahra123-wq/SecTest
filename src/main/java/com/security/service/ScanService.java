package com.security.service;

import com.security.model.ScanResult;
import com.security.model.Vulnerability;
import com.security.repository.ScanResultRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import java.util.List;

@Service
public class ScanService {

    @Autowired private CodeAnalyzerService codeAnalyzer;
    @Autowired private ApkAnalyzerService apkAnalyzer;
    @Autowired private TestGeneratorService testGenerator;
    @Autowired private PdfReportService pdfReportService;
    @Autowired private ScanResultRepository scanResultRepository;
    @Autowired private OllamaService ollamaService;

    public ScanResult scan(MultipartFile file) throws Exception {
        String fileName = file.getOriginalFilename();
        boolean isApk = fileName != null && fileName.toLowerCase().endsWith(".apk");

        List<Vulnerability> vulnerabilities;
        String language;
        String code = "";

        if (isApk) {
            language = "apk";
            vulnerabilities = apkAnalyzer.analyzeApk(file.getBytes(), fileName);
        } else {
            code = new String(file.getBytes());
            language = codeAnalyzer.detectLanguage(fileName);
            vulnerabilities = codeAnalyzer.analyzeCode(code, language);
        }

        // ── Compter par sévérité ──────────────────────────────────
        long critical = vulnerabilities.stream().filter(v -> "CRITICAL".equals(v.getSeverity())).count();
        long high     = vulnerabilities.stream().filter(v -> "HIGH".equals(v.getSeverity())).count();
        long medium   = vulnerabilities.stream().filter(v -> "MEDIUM".equals(v.getSeverity())).count();
        long low      = vulnerabilities.stream().filter(v -> "LOW".equals(v.getSeverity())).count();

        // ── Score de sécurité ─────────────────────────────────────
        int score = Math.max(0, (int)(100 - critical*25 - high*10 - medium*5 - low*2));

        // ── Security Gate ─────────────────────────────────────────
        String gateStatus = critical > 0 ? "BLOCKED" : "PASSED";

        // ── Tests standard (regex) ────────────────────────────────
        String tests = testGenerator.generateTests(vulnerabilities, language, fileName);

        // ── Enrichissement IA Ollama ──────────────────────────────
        boolean ollamaAvailable = ollamaService.isAvailable();
        if (ollamaAvailable && !vulnerabilities.isEmpty()) {
            try {
                StringBuilder aiSection = new StringBuilder();

                // Priorisation (commun CODE + APK)
                String prioritization = ollamaService.prioritizeVulnerabilities(vulnerabilities);
                aiSection.append("\n\n// ── PRIORISATION IA ────────────────────────────────\n")
                         .append("/*\n").append(prioritization).append("\n*/\n");

                if (isApk) {
                    // ── Mapping MASVS spécifique Android ─────────
                    String masvs = ollamaService.generateMASVSMappingAndroid(vulnerabilities);
                    aiSection.append("\n// ── MAPPING MASVS/MASTG ANDROID ─────────────────────\n")
                             .append("/*\n").append(masvs).append("\n*/\n");

                    // ── Analyse exported components ───────────────
                    String exported = ollamaService.analyzeExportedComponents(vulnerabilities);
                    if (!exported.isEmpty() && !exported.contains("non disponible")) {
                        aiSection.append("\n// ── ANALYSE EXPORTED COMPONENTS ─────────────────────\n")
                                 .append("/*\n").append(exported).append("\n*/\n");
                    }

                    // ── Network Security Config ───────────────────
                    String networkConfig = ollamaService.generateNetworkSecurityConfig(vulnerabilities);
                    if (!networkConfig.isEmpty() && !networkConfig.contains("non disponible")) {
                        aiSection.append("\n// ── NETWORK SECURITY CONFIG RECOMMANDÉ ──────────────\n")
                                 .append("/*\n").append(networkConfig).append("\n*/\n");
                    }

                } else {
                    // ── Mapping MASVS standard pour code source ───
                    String masvs = ollamaService.generateMASVSMapping(vulnerabilities);
                    aiSection.append("\n// ── MAPPING MASVS/MASTG ─────────────────────────────\n")
                             .append("/*\n").append(masvs).append("\n*/\n");
                }

                tests = tests + aiSection.toString();

            } catch (Exception e) {
                tests = tests + "\n// IA non disponible pour cet scan";
            }
        }

        // ── Sauvegarder ───────────────────────────────────────────
        ScanResult result = ScanResult.builder()
            .fileName(fileName)
            .fileType(isApk ? "APK" : "CODE")
            .language(language)
            .totalLines(isApk ? 0 : code.split("\n").length)
            .securityScore(score)
            .gateStatus(gateStatus)
            .generatedTests(tests)
            .criticalCount((int) critical)
            .highCount((int) high)
            .mediumCount((int) medium)
            .lowCount((int) low)
            .build();

        result = scanResultRepository.save(result);

        for (Vulnerability v : vulnerabilities) {
            v.setScanResult(result);
        }
        result.setVulnerabilities(vulnerabilities);
        result = scanResultRepository.save(result);

        return result;
    }

    public byte[] generatePdf(Long scanId) throws Exception {
        ScanResult result = scanResultRepository.findById(scanId)
            .orElseThrow(() -> new RuntimeException("Scan non trouvé: " + scanId));
        return pdfReportService.generatePdf(result);
    }

    public List<ScanResult> getHistory() {
        return scanResultRepository.findAllByOrderByScanDateDesc();
    }

    public ScanResult getScanById(Long id) {
        return scanResultRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("Scan non trouvé: " + id));
    }
}