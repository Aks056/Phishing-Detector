package com.security.phishing_detector.controller;

import com.security.phishing_detector.dto.UrlCheckRequest;
import com.security.phishing_detector.dto.UrlCheckResponse;
import com.security.phishing_detector.domain.ThreatAnalysis;
import com.security.phishing_detector.service.PhishingAnalysisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
        import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/phishing")
@CrossOrigin(origins = "*")
public class PhishingDetectionController {

    private final PhishingAnalysisService phishingAnalysisService;

    @Autowired
    public PhishingDetectionController(PhishingAnalysisService phishingAnalysisService) {
        this.phishingAnalysisService = phishingAnalysisService;
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

    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("Phishing Detection Service is operational");
    }
}
