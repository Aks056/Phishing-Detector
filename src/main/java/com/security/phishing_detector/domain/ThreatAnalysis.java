package com.security.phishing_detector.domain;

import java.util.List;

public class ThreatAnalysis {
    private final String url;
    private final boolean isPhishing;
    private final double riskScore;
    private final List<String> detectedThreats;
    private final RiskLevel riskLevel;
    
    public ThreatAnalysis(String url, boolean isPhishing, double riskScore, 
                         List<String> detectedThreats, RiskLevel riskLevel) {
        this.url = url;
        this.isPhishing = isPhishing;
        this.riskScore = riskScore;
        this.detectedThreats = detectedThreats;
        this.riskLevel = riskLevel;
    }
    
    // Getters
    public String getUrl() { return url; }
    public boolean isPhishing() { return isPhishing; }
    public double getRiskScore() { return riskScore; }
    public List<String> getDetectedThreats() { return detectedThreats; }
    public RiskLevel getRiskLevel() { return riskLevel; }
}