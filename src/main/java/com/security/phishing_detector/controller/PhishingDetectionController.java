package com.security.phishing_detector.controller;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.security.phishing_detector.domain.AnalysisHistory;
import com.security.phishing_detector.domain.ThreatAnalysis;
import com.security.phishing_detector.dto.UrlCheckRequest;
import com.security.phishing_detector.dto.UrlCheckResponse;
import com.security.phishing_detector.repository.AnalysisHistoryRepository;
import com.security.phishing_detector.service.ExportService;
import com.security.phishing_detector.service.PhishingAnalysisService;
import com.security.phishing_detector.service.ThreatIntelligenceService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/phishing")
@CrossOrigin(origins = {"http://localhost:8080", "https://localhost:8080"}, allowCredentials = "true")
public class PhishingDetectionController {

    private static final Pattern URL_PATTERN = Pattern.compile(
        "^https?://(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&//=]*)$"
    );

    private final PhishingAnalysisService phishingAnalysisService;
    private final AnalysisHistoryRepository historyRepository;
    private final ExportService exportService;
    private final ThreatIntelligenceService threatIntelligenceService;

    public PhishingDetectionController(PhishingAnalysisService phishingAnalysisService,
                                    AnalysisHistoryRepository historyRepository,
                                    ExportService exportService,
                                    ThreatIntelligenceService threatIntelligenceService) {
        this.phishingAnalysisService = phishingAnalysisService;
        this.historyRepository = historyRepository;
        this.exportService = exportService;
        this.threatIntelligenceService = threatIntelligenceService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<UrlCheckResponse> analyzeUrl(@Valid @RequestBody UrlCheckRequest request) {
        // Additional URL validation
        String url = request.getUrl();
        if (!isValidUrl(url)) {
            UrlCheckResponse errorResponse = new UrlCheckResponse();
            errorResponse.setUrl(url);
            errorResponse.setPhishing(true);
            errorResponse.setRiskScore(100.0);
            errorResponse.setRiskLevel("HIGH");
            errorResponse.setDetectedThreats(List.of("Invalid URL format"));
            errorResponse.setRecommendation("Please provide a valid URL");
            return ResponseEntity.badRequest().body(errorResponse);
        }

        // Sanitize URL
        url = sanitizeUrl(url);

        ThreatAnalysis analysis = phishingAnalysisService.analyzeUrl(url);
        UrlCheckResponse response = UrlCheckResponse.fromThreatAnalysis(analysis);

        // Add security headers
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("X-XSS-Protection", "1; mode=block");

        return ResponseEntity.ok().headers(headers).body(response);
    }

    @GetMapping("/analyze")
    public ResponseEntity<UrlCheckResponse> analyzeUrlGet(@RequestParam String url) {
        // Validate and sanitize URL
        if (!isValidUrl(url)) {
            UrlCheckResponse errorResponse = new UrlCheckResponse();
            errorResponse.setUrl(url);
            errorResponse.setPhishing(true);
            errorResponse.setRiskScore(100.0);
            errorResponse.setRiskLevel("HIGH");
            errorResponse.setDetectedThreats(List.of("Invalid URL format"));
            errorResponse.setRecommendation("Please provide a valid URL");
            return ResponseEntity.badRequest().body(errorResponse);
        }

        url = sanitizeUrl(url);

        ThreatAnalysis analysis = phishingAnalysisService.analyzeUrl(url);
        UrlCheckResponse response = UrlCheckResponse.fromThreatAnalysis(analysis);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/history")
    public ResponseEntity<List<AnalysisHistory>> getAnalysisHistory() {
        List<AnalysisHistory> history = historyRepository.findTop10ByOrderByTimestampDesc();

        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Content-Type-Options", "nosniff");
        headers.setCacheControl("no-cache, no-store, must-revalidate");

        return ResponseEntity.ok().headers(headers).body(history);
    }

    @GetMapping("/export/pdf")
    public ResponseEntity<byte[]> exportHistoryPdf() {
        byte[] pdfContent = exportService.exportHistoryToPdf();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.setContentDispositionFormData("attachment", "analysis_history.pdf");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Download-Options", "noopen");

        return ResponseEntity.ok().headers(headers).body(pdfContent);
    }

    @GetMapping("/export/csv")
    public ResponseEntity<String> exportHistoryCsv() {
        String csvContent = exportService.exportHistoryToCsv();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        headers.setContentDispositionFormData("attachment", "analysis_history.csv");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Download-Options", "noopen");

        return ResponseEntity.ok().headers(headers).body(csvContent);
    }

    @GetMapping("/threat-intelligence/status")
    public ResponseEntity<String> getThreatIntelligenceStatus() {
        String status = String.format(
            "Threat Intelligence Status: %s\nDatabase Size: %d URLs\nLast Update: %s",
            threatIntelligenceService.isEnabled() ? "Enabled" : "Disabled",
            threatIntelligenceService.getThreatDatabaseSize(),
            threatIntelligenceService.getLastUpdate()
        );

        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Content-Type-Options", "nosniff");
        headers.setCacheControl("no-cache");

        return ResponseEntity.ok().headers(headers).body(status);
    }

    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Content-Type-Options", "nosniff");
        headers.setCacheControl("no-cache");

        return ResponseEntity.ok().headers(headers).body("Phishing Detection Service is operational");
    }

    private boolean isValidUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }

        // Basic length check to prevent extremely long URLs
        if (url.length() > 2048) {
            return false;
        }

        // Check for potentially malicious patterns
        if (url.contains("javascript:") || url.contains("data:") || url.contains("vbscript:")) {
            return false;
        }

        return URL_PATTERN.matcher(url).matches();
    }

    private String sanitizeUrl(String url) {
        try {
            URI uri = new URI(url);
            // Reconstruct URL to prevent manipulation
            return new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(),
                         uri.getPort(), uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid URL format");
        }
    }
}
