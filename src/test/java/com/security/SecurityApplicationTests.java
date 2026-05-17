package com.security;

import com.security.service.CodeAnalyzerService;
import com.security.service.ApkAnalyzerService;
import com.security.service.TestGeneratorService;
import com.security.model.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class SecurityApplicationTests {

    @Autowired
    private CodeAnalyzerService codeAnalyzer;

    @Autowired
    private TestGeneratorService testGenerator;

    @Test
    @DisplayName("Contexte Spring Boot se charge correctement")
    void contextLoads() {
        assertNotNull(codeAnalyzer);
        assertNotNull(testGenerator);
    }

    @Test
    @DisplayName("Détecte SQL Injection dans du code Java")
    void detectsSqlInjectionInJava() {
        String code = """
            public void getUser(String username) {
                String query = "SELECT * FROM users WHERE name='" + username + "'";
                stmt.execute(query);
            }
            """;
        List<Vulnerability> vulns = codeAnalyzer.analyzeCode(code, "java");
        assertTrue(vulns.stream().anyMatch(v -> v.getName().contains("SQL Injection")),
            "SQL Injection devrait être détectée");
    }

    @Test
    @DisplayName("Détecte Hardcoded Secret dans du code Java")
    void detectsHardcodedSecret() {
        String code = """
            private String password = "admin123";
            private String apiKey = "sk-1234567890abcdef";
            """;
        List<Vulnerability> vulns = codeAnalyzer.analyzeCode(code, "java");
        assertTrue(vulns.stream().anyMatch(v -> v.getName().contains("Hardcoded")),
            "Hardcoded secret devrait être détecté");
    }

    @Test
    @DisplayName("Détecte Weak Hash MD5 dans du code Java")
    void detectsWeakHash() {
        String code = """
            MessageDigest md = MessageDigest.getInstance("MD5");
            """;
        List<Vulnerability> vulns = codeAnalyzer.analyzeCode(code, "java");
        assertTrue(vulns.stream().anyMatch(v -> v.getName().contains("Weak Hash")),
            "MD5 devrait être détecté comme hash faible");
    }

    @Test
    @DisplayName("Détecte SQL Injection dans du code Python")
    void detectsSqlInjectionInPython() {
        String code = """
            def get_user(username):
                query = "SELECT * FROM users WHERE name='" + username + "'"
                cursor.execute(query)
            """;
        List<Vulnerability> vulns = codeAnalyzer.analyzeCode(code, "python");
        assertTrue(vulns.stream().anyMatch(v -> v.getName().contains("SQL Injection")),
            "SQL Injection Python devrait être détectée");
    }

    @Test
    @DisplayName("Code sécurisé ne génère aucune vulnérabilité")
    void cleanCodeHasNoVulnerabilities() {
        String code = """
            public void getUser(Long id) {
                PreparedStatement pstmt = conn.prepareStatement(
                    "SELECT * FROM users WHERE id = ?"
                );
                pstmt.setLong(1, id);
                pstmt.executeQuery();
            }
            """;
        List<Vulnerability> vulns = codeAnalyzer.analyzeCode(code, "java");
        assertTrue(vulns.stream().noneMatch(v -> v.getName().contains("SQL Injection")),
            "Code sécurisé ne devrait pas avoir de SQL Injection");
    }

    @Test
    @DisplayName("Génère des tests JUnit à partir des vulnérabilités")
    void generatesJUnitTests() {
        String code = "private String password = \"admin123\";";
        List<Vulnerability> vulns = codeAnalyzer.analyzeCode(code, "java");
        String tests = testGenerator.generateTests(vulns, "java", "Test.java");

        assertNotNull(tests);
        assertTrue(tests.contains("@Test"), "Les tests générés doivent contenir @Test");
        assertTrue(tests.contains("import org.junit.jupiter.api.Test"), "Import JUnit requis");
    }

    @Test
    @DisplayName("Détecte correctement le langage depuis l extension")
    void detectsLanguage() {
        assertEquals("java", codeAnalyzer.detectLanguage("App.java"));
        assertEquals("python", codeAnalyzer.detectLanguage("app.py"));
        assertEquals("javascript", codeAnalyzer.detectLanguage("app.js"));
    }

    @Test
    @DisplayName("Sévérité CRITICAL assignée pour SQL Injection")
    void criticalSeverityForSqlInjection() {
        String code = "stmt.execute(\"SELECT * FROM users WHERE name='\" + username + \"'\");";
        List<Vulnerability> vulns = codeAnalyzer.analyzeCode(code, "java");
        assertTrue(vulns.stream()
            .filter(v -> v.getName().contains("SQL Injection"))
            .anyMatch(v -> "CRITICAL".equals(v.getSeverity())),
            "SQL Injection doit avoir sévérité CRITICAL");
    }
}
