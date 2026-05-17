package com.security.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import com.security.model.Vulnerability;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class OllamaService {

    private static final String OLLAMA_URL = "http://localhost:11434/api/generate";
    private static final String MODEL = "llama3.2";

    private final OkHttpClient client = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .build();

    private final ObjectMapper mapper = new ObjectMapper();

    // ── Générer un test JUnit intelligent ────────────────────────
    public String generateSmartTest(Vulnerability vuln, String originalCode) {
        String prompt = String.format(
            "Generate a JUnit 5 test in Java that verifies this security vulnerability does not exist. " +
            "Vulnerability: %s (CWE: %s), Line %d: %s. " +
            "Return ONLY the Java test method code, no explanation.",
            vuln.getName(), vuln.getCwe(), vuln.getLineNumber(), vuln.getLineContent()
        );
        return callOllama(prompt, 300);
    }

    // ── Expliquer le risque en français ──────────────────────────
    public String explainRisk(Vulnerability vuln) {
        String prompt = String.format(
            "En 2 phrases courtes en français, explique le risque de cette vulnérabilité: %s (CWE: %s). Code: %s",
            vuln.getName(), vuln.getCwe(), vuln.getLineContent()
        );
        return callOllama(prompt, 150);
    }

    // ── Prioriser les vulnérabilités ──────────────────────────────
    public String prioritizeVulnerabilities(List<Vulnerability> vulns) {
        StringBuilder list = new StringBuilder();
        for (int i = 0; i < Math.min(vulns.size(), 5); i++) {
            Vulnerability v = vulns.get(i);
            list.append(String.format("%d. [%s] %s\n", i+1, v.getSeverity(), v.getName()));
        }
        String prompt = String.format(
            "En français, donne l'ordre de priorité de correction pour ces vulnérabilités (réponse courte max 5 lignes):\n%s",
            list.toString()
        );
        return callOllama(prompt, 200);
    }

    // ── Mapping MASVS ─────────────────────────────────────────────
    public String generateMASVSMapping(List<Vulnerability> vulns) {
        StringBuilder list = new StringBuilder();
        for (int i = 0; i < Math.min(vulns.size(), 3); i++) {
            Vulnerability v = vulns.get(i);
            list.append(String.format("- %s (%s)\n", v.getName(), v.getCwe()));
        }
        String prompt = String.format(
            "Map these vulnerabilities to MASVS controls (short answer, max 3 lines):\n%s",
            list.toString()
        );
        return callOllama(prompt, 150);
    }

    // ── Appel HTTP à Ollama ───────────────────────────────────────
    private String callOllama(String prompt, int maxTokens) {
        try {
            String requestBody = mapper.writeValueAsString(new java.util.HashMap<>() {{
                put("model", MODEL);
                put("prompt", prompt);
                put("stream", false);
                put("options", new java.util.HashMap<>() {{
                    put("temperature", 0.2);
                    put("num_predict", maxTokens);
                    put("num_ctx", 512);
                }});
            }});

            Request request = new Request.Builder()
                    .url(OLLAMA_URL)
                    .post(RequestBody.create(requestBody, MediaType.parse("application/json")))
                    .build();

            try (Response response = client.newCall(request).execute()) {
                if (!response.isSuccessful()) return "IA non disponible";
                JsonNode node = mapper.readTree(response.body().string());
                return node.get("response").asText().trim();
            }
        } catch (Exception e) {
            return "IA non disponible: " + e.getMessage();
        }
    }

    // ── Vérifier si Ollama est disponible ────────────────────────
    public boolean isAvailable() {
        try {
            Request request = new Request.Builder()
                    .url("http://localhost:11434/api/tags")
                    .get()
                    .build();
            try (Response response = client.newCall(request).execute()) {
                return response.isSuccessful();
            }
        } catch (Exception e) {
            return false;
        }
    }
}