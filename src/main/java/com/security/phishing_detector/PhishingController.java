package com.security.phishing_detector;

import com.security.phishing_detector.domain.ThreatAnalysis;
import com.security.phishing_detector.service.PhishingAnalysisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class PhishingController {

    private final PhishingAnalysisService phishingAnalysisService;

    @Autowired
    public PhishingController(PhishingAnalysisService phishingAnalysisService) {
        this.phishingAnalysisService = phishingAnalysisService;
    }

    @PostMapping("/check-url")
    public String checkUrl(@RequestParam("url_to_check") String url, Model model) {
        ThreatAnalysis analysis = phishingAnalysisService.analyzeUrl(url);

        model.addAttribute("reasons", analysis.getDetectedThreats());
        model.addAttribute("isPhishing", analysis.isPhishing());
        model.addAttribute("checkedUrl", analysis.getUrl());
        model.addAttribute("riskScore", analysis.getRiskScore());
        model.addAttribute("riskLevel", analysis.getRiskLevel());

        return "result";
    }
}