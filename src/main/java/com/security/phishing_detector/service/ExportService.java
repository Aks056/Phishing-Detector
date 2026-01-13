package com.security.phishing_detector.service;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import com.opencsv.CSVWriter;
import com.security.phishing_detector.domain.AnalysisHistory;
import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.repository.AnalysisHistoryRepository;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class ExportService {

    private final AnalysisHistoryRepository historyRepository;

    public ExportService(AnalysisHistoryRepository historyRepository) {
        this.historyRepository = historyRepository;
    }

    public byte[] exportHistoryToPdf() {
        List<AnalysisHistory> history = historyRepository.findTop10ByOrderByTimestampDesc();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            PdfWriter writer = new PdfWriter(baos);
            PdfDocument pdf = new PdfDocument(writer);
            Document document = new Document(pdf);

            document.add(new Paragraph("Phishing Detection Analysis History")
                    .setTextAlignment(TextAlignment.CENTER)
                    .setFontSize(18));

            document.add(new Paragraph("Generated on: " + java.time.LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")))
                    .setTextAlignment(TextAlignment.RIGHT));

            document.add(new Paragraph("\n"));

            Table table = new Table(UnitValue.createPercentArray(new float[]{20, 30, 15, 20, 15}));
            table.setWidth(UnitValue.createPercentValue(100));

            table.addHeaderCell("Timestamp");
            table.addHeaderCell("URL");
            table.addHeaderCell("Risk Score");
            table.addHeaderCell("Threat Detected");
            table.addHeaderCell("Details");

            for (AnalysisHistory item : history) {
                table.addCell(item.getTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
                table.addCell(item.getUrl());
                table.addCell(String.format("%.2f", item.getTotalRiskScore()));
                table.addCell(item.isThreatDetected() ? "Yes" : "No");

                StringBuilder details = new StringBuilder();
                for (DetectionResult result : item.getResults()) {
                    if (result.getThreatDescription() != null) {
                        details.append(result.getThreatDescription()).append("; ");
                    }
                }
                table.addCell(details.toString());
            }

            document.add(table);
            document.close();

        } catch (Exception e) {
            throw new RuntimeException("Error generating PDF", e);
        }

        return baos.toByteArray();
    }

    public String exportHistoryToCsv() {
        List<AnalysisHistory> history = historyRepository.findTop10ByOrderByTimestampDesc();

        StringWriter writer = new StringWriter();
        CSVWriter csvWriter = new CSVWriter(writer);

        // Header
        csvWriter.writeNext(new String[]{"Timestamp", "URL", "Risk Score", "Threat Detected", "Details"});

        // Data
        for (AnalysisHistory item : history) {
            StringBuilder details = new StringBuilder();
            for (DetectionResult result : item.getResults()) {
                if (result.getThreatDescription() != null) {
                    details.append(result.getThreatDescription()).append("; ");
                }
            }

            csvWriter.writeNext(new String[]{
                item.getTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                item.getUrl(),
                String.format("%.2f", item.getTotalRiskScore()),
                item.isThreatDetected() ? "Yes" : "No",
                details.toString()
            });
        }

        try {
            csvWriter.close();
        } catch (Exception e) {
            // ignore
        }

        return writer.toString();
    }
}