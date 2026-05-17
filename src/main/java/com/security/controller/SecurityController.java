package com.security.controller;

import com.security.model.ScanResult;
import com.security.service.ScanService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class SecurityController {

    @Autowired
    private ScanService scanService;

    // ── POST /api/analyze ─────────────────────────────────────────
    @PostMapping(value = "/analyze", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> analyze(@RequestParam("file") MultipartFile file) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Fichier vide"));
            }

            String fileName = file.getOriginalFilename();
            boolean validExt = fileName != null && (
                fileName.endsWith(".java") || fileName.endsWith(".py") ||
                fileName.endsWith(".js")   || fileName.endsWith(".ts") ||
                fileName.endsWith(".apk")
            );

            if (!validExt) {
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "Format non supporté. Utilisez .java, .py, .js, .ts ou .apk"
                ));
            }

            ScanResult result = scanService.scan(file);
            return ResponseEntity.ok(toResponse(result));

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    // ── GET /api/report/{id}/pdf ──────────────────────────────────
    @GetMapping("/report/{id}/pdf")
    public ResponseEntity<byte[]> downloadPdf(@PathVariable Long id) {
        try {
            byte[] pdf = scanService.generatePdf(id);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDisposition(
                ContentDisposition.attachment().filename("security_report_" + id + ".pdf").build()
            );
            return ResponseEntity.ok().headers(headers).body(pdf);
        } catch (Exception e) {
            return ResponseEntity.status(500).build();
        }
    }

    // ── GET /api/tests/{id} ───────────────────────────────────────
    @GetMapping("/tests/{id}")
    public ResponseEntity<?> getTests(@PathVariable Long id) {
        try {
            ScanResult result = scanService.getScanById(id);
            return ResponseEntity.ok(Map.of(
                "scanId", id,
                "fileName", result.getFileName(),
                "tests", result.getGeneratedTests()
            ));
        } catch (Exception e) {
            return ResponseEntity.status(404).body(Map.of("error", e.getMessage()));
        }
    }

    // ── GET /api/history ──────────────────────────────────────────
    @GetMapping("/history")
    public ResponseEntity<?> getHistory() {
        try {
            List<ScanResult> history = scanService.getHistory();
            List<Map<String, Object>> response = history.stream()
                .map(this::toSummary)
                .toList();
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    // ── GET /api/history/{id} ─────────────────────────────────────
    @GetMapping("/history/{id}")
    public ResponseEntity<?> getScanDetail(@PathVariable Long id) {
        try {
            ScanResult result = scanService.getScanById(id);
            return ResponseEntity.ok(toResponse(result));
        } catch (Exception e) {
            return ResponseEntity.status(404).body(Map.of("error", e.getMessage()));
        }
    }

    // ── GET /api/health ───────────────────────────────────────────
    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "service", "Security Regression Test Generator",
            "version", "1.0.0"
        ));
    }

    // ── HELPERS ───────────────────────────────────────────────────
    private Map<String, Object> toResponse(ScanResult r) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", r.getId());
        map.put("fileName", r.getFileName());
        map.put("fileType", r.getFileType());
        map.put("language", r.getLanguage());
        map.put("totalLines", r.getTotalLines());
        map.put("securityScore", r.getSecurityScore());
        map.put("gateStatus", r.getGateStatus());
        map.put("scanDate", r.getScanDate());
        map.put("criticalCount", r.getCriticalCount());
        map.put("highCount", r.getHighCount());
        map.put("mediumCount", r.getMediumCount());
        map.put("lowCount", r.getLowCount());
        map.put("generatedTests", r.getGeneratedTests());

        if (r.getVulnerabilities() != null) {
            List<Map<String, Object>> vulns = r.getVulnerabilities().stream().map(v -> {
                Map<String, Object> vm = new LinkedHashMap<>();
                vm.put("id", v.getId());
                vm.put("ruleId", v.getRuleId());
                vm.put("name", v.getName());
                vm.put("severity", v.getSeverity());
                vm.put("category", v.getCategory());
                vm.put("cwe", v.getCwe());
                vm.put("description", v.getDescription());
                vm.put("lineNumber", v.getLineNumber());
                vm.put("lineContent", v.getLineContent());
                vm.put("recommendation", v.getRecommendation());
                return vm;
            }).toList();
            map.put("vulnerabilities", vulns);
        }

        map.put("pdfUrl", "/api/report/" + r.getId() + "/pdf");
        map.put("testsUrl", "/api/tests/" + r.getId());
        return map;
    }

    private Map<String, Object> toSummary(ScanResult r) {
        return Map.of(
            "id", r.getId(),
            "fileName", r.getFileName(),
            "fileType", r.getFileType(),
            "securityScore", r.getSecurityScore(),
            "gateStatus", r.getGateStatus(),
            "scanDate", r.getScanDate(),
            "criticalCount", r.getCriticalCount(),
            "totalVulnerabilities", r.getCriticalCount() + r.getHighCount() + r.getMediumCount() + r.getLowCount(),
            "pdfUrl", "/api/report/" + r.getId() + "/pdf"
        );
    }
}
