package com.security.service;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import com.security.model.ScanResult;
import com.security.model.Vulnerability;
import org.springframework.stereotype.Service;
import java.io.ByteArrayOutputStream;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class PdfReportService {

    // ── COLORS ───────────────────────────────────────────────────
    private static final BaseColor COLOR_BG       = new BaseColor(8, 12, 26);
    private static final BaseColor COLOR_ACCENT   = new BaseColor(59, 130, 246);
    private static final BaseColor COLOR_CRITICAL = new BaseColor(248, 113, 113);
    private static final BaseColor COLOR_HIGH     = new BaseColor(251, 146, 60);
    private static final BaseColor COLOR_MEDIUM   = new BaseColor(251, 191, 36);
    private static final BaseColor COLOR_LOW      = new BaseColor(52, 211, 153);
    private static final BaseColor COLOR_WHITE    = BaseColor.WHITE;
    private static final BaseColor COLOR_GRAY     = new BaseColor(100, 116, 139);
    private static final BaseColor COLOR_SURFACE  = new BaseColor(17, 24, 39);
    private static final BaseColor COLOR_SURFACE2 = new BaseColor(26, 37, 54);

    // ── FONTS ────────────────────────────────────────────────────
    private static final Font FONT_TITLE    = new Font(Font.FontFamily.HELVETICA, 22, Font.BOLD, COLOR_WHITE);
    private static final Font FONT_SUBTITLE = new Font(Font.FontFamily.HELVETICA, 11, Font.NORMAL, COLOR_GRAY);
    private static final Font FONT_H2       = new Font(Font.FontFamily.HELVETICA, 14, Font.BOLD, COLOR_WHITE);
    private static final Font FONT_H3       = new Font(Font.FontFamily.HELVETICA, 11, Font.BOLD, COLOR_WHITE);
    private static final Font FONT_BODY     = new Font(Font.FontFamily.HELVETICA, 9, Font.NORMAL, COLOR_WHITE);
    private static final Font FONT_BODY_GRAY= new Font(Font.FontFamily.HELVETICA, 9, Font.NORMAL, COLOR_GRAY);
    private static final Font FONT_CODE     = new Font(Font.FontFamily.COURIER, 8, Font.NORMAL, new BaseColor(165, 180, 252));
    private static final Font FONT_SMALL    = new Font(Font.FontFamily.HELVETICA, 8, Font.NORMAL, COLOR_GRAY);

    public byte[] generatePdf(ScanResult scanResult) throws DocumentException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4, 40, 40, 50, 50);
        PdfWriter writer = PdfWriter.getInstance(document, baos);

        // Page background
        writer.setPageEvent(new PdfPageEventHelper() {
            @Override
            public void onEndPage(PdfWriter writer, Document document) {
                PdfContentByte canvas = writer.getDirectContentUnder();
                canvas.setColorFill(COLOR_BG);
                canvas.rectangle(0, 0, document.getPageSize().getWidth(), document.getPageSize().getHeight());
                canvas.fill();
            }
        });

        document.open();

        // ── HEADER ──────────────────────────────────────────────
        addHeader(document, scanResult);
        document.add(Chunk.NEWLINE);

        // ── SCORE BANNER ─────────────────────────────────────────
        addScoreBanner(document, scanResult);
        document.add(Chunk.NEWLINE);

        // ── KPI TABLE ────────────────────────────────────────────
        addKpiTable(document, scanResult);
        document.add(Chunk.NEWLINE);

        // ── SECURITY GATE ─────────────────────────────────────────
        addSecurityGate(document, scanResult);
        document.add(Chunk.NEWLINE);

        // ── VULNERABILITIES ───────────────────────────────────────
        if (scanResult.getVulnerabilities() != null && !scanResult.getVulnerabilities().isEmpty()) {
            addVulnerabilities(document, scanResult.getVulnerabilities());
            document.add(Chunk.NEWLINE);
        }

        // ── GENERATED TESTS ───────────────────────────────────────
        if (scanResult.getGeneratedTests() != null && !scanResult.getGeneratedTests().isEmpty()) {
            addGeneratedTests(document, scanResult.getGeneratedTests());
        }

        // ── FOOTER ────────────────────────────────────────────────
        addFooter(document, scanResult);

        document.close();
        return baos.toByteArray();
    }

    private void addHeader(Document doc, ScanResult scan) throws DocumentException {
        PdfPTable header = new PdfPTable(1);
        header.setWidthPercentage(100);

        PdfPCell cell = new PdfPCell();
        cell.setBackgroundColor(COLOR_SURFACE);
        cell.setBorderColor(COLOR_ACCENT);
        cell.setBorderWidth(1f);
        cell.setPadding(20);

        Paragraph title = new Paragraph("🔒 SECURITY REGRESSION REPORT", FONT_TITLE);
        title.setAlignment(Element.ALIGN_CENTER);
        cell.addElement(title);

        Paragraph sub = new Paragraph("Security Regression Test Generator — DevSecOps Pipeline", FONT_SUBTITLE);
        sub.setAlignment(Element.ALIGN_CENTER);
        cell.addElement(sub);

        Paragraph meta = new Paragraph(
            "Fichier: " + scan.getFileName() + "   |   "
            + "Type: " + scan.getFileType() + "   |   "
            + "Date: " + scan.getScanDate().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")),
            FONT_SMALL
        );
        meta.setAlignment(Element.ALIGN_CENTER);
        meta.setSpacingBefore(8);
        cell.addElement(meta);

        header.addCell(cell);
        doc.add(header);
    }

    private void addScoreBanner(Document doc, ScanResult scan) throws DocumentException {
        int score = scan.getSecurityScore();
        BaseColor scoreColor = score >= 80 ? COLOR_LOW : score >= 50 ? COLOR_MEDIUM : COLOR_CRITICAL;
        String scoreLabel = score >= 80 ? "✅ BON" : score >= 50 ? "⚠️ MOYEN" : "❌ CRITIQUE";

        PdfPTable table = new PdfPTable(2);
        table.setWidthPercentage(100);
        table.setWidths(new float[]{1, 3});

        // Score circle cell
        PdfPCell scoreCell = new PdfPCell();
        scoreCell.setBackgroundColor(COLOR_SURFACE2);
        scoreCell.setBorderColor(scoreColor);
        scoreCell.setBorderWidth(2f);
        scoreCell.setPadding(15);
        scoreCell.setHorizontalAlignment(Element.ALIGN_CENTER);

        Font scoreFont = new Font(Font.FontFamily.HELVETICA, 36, Font.BOLD, scoreColor);
        Paragraph scoreP = new Paragraph(score + "/100", scoreFont);
        scoreP.setAlignment(Element.ALIGN_CENTER);
        scoreCell.addElement(scoreP);

        Font labelFont = new Font(Font.FontFamily.HELVETICA, 12, Font.BOLD, scoreColor);
        Paragraph labelP = new Paragraph(scoreLabel, labelFont);
        labelP.setAlignment(Element.ALIGN_CENTER);
        scoreCell.addElement(labelP);

        // Info cell
        PdfPCell infoCell = new PdfPCell();
        infoCell.setBackgroundColor(COLOR_SURFACE);
        infoCell.setBorderColor(COLOR_SURFACE2);
        infoCell.setBorderWidth(1f);
        infoCell.setPadding(15);

        Paragraph infoTitle = new Paragraph("Score de Sécurité", FONT_H2);
        infoCell.addElement(infoTitle);

        String desc = score >= 80
            ? "Aucune vulnérabilité critique. Le code respecte les bonnes pratiques de sécurité."
            : "Des vulnérabilités ont été détectées. Corrigez en priorité les failles CRITICAL et HIGH.";

        Paragraph infoDesc = new Paragraph(desc, FONT_BODY_GRAY);
        infoDesc.setSpacingBefore(8);
        infoCell.addElement(infoDesc);

        Paragraph formula = new Paragraph(
            "Formule: 100 - (CRITICAL×25 + HIGH×10 + MEDIUM×5 + LOW×2)",
            FONT_SMALL
        );
        formula.setSpacingBefore(6);
        infoCell.addElement(formula);

        table.addCell(scoreCell);
        table.addCell(infoCell);
        doc.add(table);
    }

    private void addKpiTable(Document doc, ScanResult scan) throws DocumentException {
        addSectionTitle(doc, "📊 Résumé des Vulnérabilités");

        PdfPTable table = new PdfPTable(5);
        table.setWidthPercentage(100);

        addKpiCell(table, String.valueOf(scan.getVulnerabilities() != null ? scan.getVulnerabilities().size() : 0), "TOTAL", COLOR_ACCENT);
        addKpiCell(table, String.valueOf(scan.getCriticalCount()), "CRITICAL", COLOR_CRITICAL);
        addKpiCell(table, String.valueOf(scan.getHighCount()), "HIGH", COLOR_HIGH);
        addKpiCell(table, String.valueOf(scan.getMediumCount()), "MEDIUM", COLOR_MEDIUM);
        addKpiCell(table, String.valueOf(scan.getLowCount()), "LOW", COLOR_LOW);

        doc.add(table);
    }

    private void addKpiCell(PdfPTable table, String number, String label, BaseColor color) {
        PdfPCell cell = new PdfPCell();
        cell.setBackgroundColor(COLOR_SURFACE);
        cell.setBorderColor(COLOR_SURFACE2);
        cell.setBorderWidth(1f);
        cell.setPadding(12);
        cell.setHorizontalAlignment(Element.ALIGN_CENTER);

        Font numFont = new Font(Font.FontFamily.HELVETICA, 24, Font.BOLD, color);
        Paragraph num = new Paragraph(number, numFont);
        num.setAlignment(Element.ALIGN_CENTER);
        cell.addElement(num);

        Font lblFont = new Font(Font.FontFamily.HELVETICA, 8, Font.BOLD, color);
        Paragraph lbl = new Paragraph(label, lblFont);
        lbl.setAlignment(Element.ALIGN_CENTER);
        cell.addElement(lbl);

        table.addCell(cell);
    }

    private void addSecurityGate(Document doc, ScanResult scan) throws DocumentException {
        addSectionTitle(doc, "🚦 Security Gate CI/CD");

        boolean blocked = "BLOCKED".equals(scan.getGateStatus());
        BaseColor gateColor = blocked ? COLOR_CRITICAL : COLOR_LOW;
        String gateText = blocked
            ? "❌ BUILD BLOQUÉ — Vulnérabilités critiques détectées. Déploiement refusé."
            : "✅ BUILD AUTORISÉ — Aucune vulnérabilité bloquante. Déploiement autorisé.";

        PdfPTable table = new PdfPTable(1);
        table.setWidthPercentage(100);

        PdfPCell cell = new PdfPCell();
        cell.setBackgroundColor(COLOR_SURFACE);
        cell.setBorderColor(gateColor);
        cell.setBorderWidth(2f);
        cell.setPadding(15);

        Font gateFont = new Font(Font.FontFamily.HELVETICA, 13, Font.BOLD, gateColor);
        Paragraph p = new Paragraph(gateText, gateFont);
        p.setAlignment(Element.ALIGN_CENTER);
        cell.addElement(p);

        table.addCell(cell);
        doc.add(table);
    }

    private void addVulnerabilities(Document doc, List<Vulnerability> vulns) throws DocumentException {
        addSectionTitle(doc, "🔍 Détail des Vulnérabilités (" + vulns.size() + ")");

        PdfPTable table = new PdfPTable(5);
        table.setWidthPercentage(100);
        table.setWidths(new float[]{1.2f, 2f, 1f, 0.8f, 3f});

        // Header
        String[] headers = {"Sévérité", "Nom", "CWE", "Ligne", "Recommandation"};
        for (String h : headers) {
            PdfPCell hCell = new PdfPCell(new Phrase(h, FONT_H3));
            hCell.setBackgroundColor(COLOR_SURFACE2);
            hCell.setBorderColor(COLOR_SURFACE2);
            hCell.setPadding(8);
            table.addCell(hCell);
        }

        // Rows
        for (Vulnerability v : vulns) {
            BaseColor sevColor = switch (v.getSeverity()) {
                case "CRITICAL" -> COLOR_CRITICAL;
                case "HIGH"     -> COLOR_HIGH;
                case "MEDIUM"   -> COLOR_MEDIUM;
                case "LOW"      -> COLOR_LOW;
                default         -> COLOR_GRAY;
            };

            Font sevFont = new Font(Font.FontFamily.HELVETICA, 8, Font.BOLD, sevColor);

            addTableCell(table, v.getSeverity(), sevFont, COLOR_SURFACE);
            addTableCell(table, v.getName(), FONT_BODY, COLOR_SURFACE);
            addTableCell(table, v.getCwe(), FONT_CODE, COLOR_SURFACE);
            addTableCell(table, v.getLineNumber() != null ? "L." + v.getLineNumber() : "—", FONT_BODY, COLOR_SURFACE);
            addTableCell(table, v.getRecommendation(), FONT_SMALL, COLOR_SURFACE);
        }

        doc.add(table);
    }

    private void addGeneratedTests(Document doc, String tests) throws DocumentException {
        addSectionTitle(doc, "🧪 Tests de Sécurité Générés");

        PdfPTable table = new PdfPTable(1);
        table.setWidthPercentage(100);

        PdfPCell cell = new PdfPCell();
        cell.setBackgroundColor(new BaseColor(10, 15, 26));
        cell.setBorderColor(COLOR_SURFACE2);
        cell.setBorderWidth(1f);
        cell.setPadding(12);

        String preview = tests.length() > 2000 ? tests.substring(0, 2000) + "\n\n// ... (tests tronqués pour le PDF)" : tests;
        Paragraph p = new Paragraph(preview, FONT_CODE);
        cell.addElement(p);

        table.addCell(cell);
        doc.add(table);
    }

    private void addFooter(Document doc, ScanResult scan) throws DocumentException {
        doc.add(Chunk.NEWLINE);
        Paragraph footer = new Paragraph(
            "Security Regression Test Generator — Projet 13 DevSecOps — "
            + scan.getScanDate().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")),
            FONT_SMALL
        );
        footer.setAlignment(Element.ALIGN_CENTER);
        doc.add(footer);
    }

    private void addSectionTitle(Document doc, String title) throws DocumentException {
        Paragraph p = new Paragraph(title, FONT_H2);
        p.setSpacingBefore(10);
        p.setSpacingAfter(8);
        doc.add(p);
    }

    private void addTableCell(PdfPTable table, String text, Font font, BaseColor bg) {
        PdfPCell cell = new PdfPCell(new Phrase(text != null ? text : "—", font));
        cell.setBackgroundColor(bg);
        cell.setBorderColor(COLOR_SURFACE2);
        cell.setPadding(6);
        cell.setVerticalAlignment(Element.ALIGN_MIDDLE);
        table.addCell(cell);
    }
}
