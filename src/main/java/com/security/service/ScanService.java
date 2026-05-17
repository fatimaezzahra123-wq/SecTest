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

    public ScanResult scan(MultipartFile file) throws Exception {
        String fileName = file.getOriginalFilename();
        boolean isApk = fileName != null && fileName.toLowerCase().endsWith(".apk");

        List<Vulnerability> vulnerabilities;
        String language;

        if (isApk) {
            language = "apk";
            vulnerabilities = apkAnalyzer.analyzeApk(file.getBytes(), fileName);
        } else {
            String code = new String(file.getBytes());
            language = codeAnalyzer.detectLanguage(fileName);
            vulnerabilities = codeAnalyzer.analyzeCode(code, language);
        }

        // Compter par sévérité
        long critical = vulnerabilities.stream().filter(v -> "CRITICAL".equals(v.getSeverity())).count();
        long high     = vulnerabilities.stream().filter(v -> "HIGH".equals(v.getSeverity())).count();
        long medium   = vulnerabilities.stream().filter(v -> "MEDIUM".equals(v.getSeverity())).count();
        long low      = vulnerabilities.stream().filter(v -> "LOW".equals(v.getSeverity())).count();

        // Score de sécurité
        int score = Math.max(0, (int)(100 - critical*25 - high*10 - medium*5 - low*2));

        // Security Gate
        String gateStatus = critical > 0 ? "BLOCKED" : "PASSED";

        // Générer les tests
        String tests = testGenerator.generateTests(vulnerabilities, language, fileName);

        // Sauvegarder
        ScanResult result = ScanResult.builder()
            .fileName(fileName)
            .fileType(isApk ? "APK" : "CODE")
            .language(language)
            .totalLines(isApk ? 0 : new String(file.getBytes()).split("\n").length)
            .securityScore(score)
            .gateStatus(gateStatus)
            .generatedTests(tests)
            .criticalCount((int) critical)
            .highCount((int) high)
            .mediumCount((int) medium)
            .lowCount((int) low)
            .build();

        result = scanResultRepository.save(result);

        // Lier les vulnérabilités
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
