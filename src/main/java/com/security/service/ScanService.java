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

        // ── Générer les tests (regex standard) ───────────────────
        String tests = testGenerator.generateTests(vulnerabilities, language, fileName);

        // ── Enrichissement IA rapide (seulement 1 vuln CRITICAL) ──
        boolean ollamaAvailable = ollamaService.isAvailable();
        if (ollamaAvailable && !vulnerabilities.isEmpty()) {
            try {
                // Priorisation rapide (1 seul appel IA)
                String prioritization = ollamaService.prioritizeVulnerabilities(vulnerabilities);

                // Mapping MASVS rapide (1 seul appel IA)
                String masvs = ollamaService.generateMASVSMapping(vulnerabilities);

                // Ajouter au rapport de tests
                tests = tests + "\n\n// ── PRIORISATION IA ────────────────────────────────\n"
                      + "/*\n" + prioritization + "\n*/\n"
                      + "\n// ── MAPPING MASVS/MASTG ─────────────────────────────\n"
                      + "/*\n" + masvs + "\n*/\n";
            } catch (Exception e) {
                // Si Ollama timeout, on continue sans IA
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