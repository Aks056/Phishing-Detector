package com.security.phishing_detector.controller;

import com.security.phishing_detector.dto.UrlCheckRequest;
import com.security.phishing_detector.dto.UrlCheckResponse;
import com.security.phishing_detector.domain.AnalysisHistory;
import com.security.phishing_detector.domain.ThreatAnalysis;
import com.security.phishing_detector.repository.AnalysisHistoryRepository;
import com.security.phishing_detector.service.ExportService;
import com.security.phishing_detector.service.PhishingAnalysisService;
import com.security.phishing_detector.service.ThreatIntelligenceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
        import jakarta.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/api/v1/phishing")
@CrossOrigin(origins = "*")
public class PhishingDetectionController {

    private final PhishingAnalysisService phishingAnalysisService;
    private final AnalysisHistoryRepository historyRepository;
    private final ExportService exportService;
    private final ThreatIntelligenceService threatIntelligenceService;

    @Autowired
    public PhishingDetectionController(PhishingAnalysisService phishingAnalysisService, AnalysisHistoryRepository historyRepository, ExportService exportService, ThreatIntelligenceService threatIntelligenceService) {
        this.phishingAnalysisService = phishingAnalysisService;
        this.historyRepository = historyRepository;
        this.exportService = exportService;
        this.threatIntelligenceService = threatIntelligenceService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<UrlCheckResponse> analyzeUrl(@Valid @RequestBody UrlCheckRequest request) {
        ThreatAnalysis analysis = phishingAnalysisService.analyzeUrl(request.getUrl());
        UrlCheckResponse response = UrlCheckResponse.fromThreatAnalysis(analysis);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/analyze")
    public ResponseEntity<UrlCheckResponse> analyzeUrlGet(@RequestParam String url) {
        ThreatAnalysis analysis = phishingAnalysisService.analyzeUrl(url);
        UrlCheckResponse response = UrlCheckResponse.fromThreatAnalysis(analysis);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/history")
    public ResponseEntity<List<AnalysisHistory>> getAnalysisHistory() {
        List<AnalysisHistory> history = historyRepository.findTop10ByOrderByTimestampDesc();
        return ResponseEntity.ok(history);
    }

    @GetMapping("/export/pdf")
    public ResponseEntity<byte[]> exportHistoryPdf() {
        byte[] pdfContent = exportService.exportHistoryToPdf();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.setContentDispositionFormData("attachment", "analysis_history.pdf");

        return ResponseEntity.ok()
                .headers(headers)
                .body(pdfContent);
    }

    @GetMapping("/export/csv")
    public ResponseEntity<String> exportHistoryCsv() {
        String csvContent = exportService.exportHistoryToCsv();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        headers.setContentDispositionFormData("attachment", "analysis_history.csv");

        return ResponseEntity.ok()
                .headers(headers)
                .body(csvContent);
    }

    @GetMapping("/threat-intelligence/status")
    public ResponseEntity<String> getThreatIntelligenceStatus() {
        return ResponseEntity.ok(String.format(
            "Threat Intelligence Status: %s\nDatabase Size: %d URLs\nLast Update: %s",
            threatIntelligenceService.isEnabled() ? "Enabled" : "Disabled",
            threatIntelligenceService.getThreatDatabaseSize(),
            threatIntelligenceService.getLastUpdate()
        ));
    }

    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("Phishing Detection Service is operational");
    }
}
