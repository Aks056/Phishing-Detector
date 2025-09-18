package com.security.phishing_detector.dto;

import com.security.phishing_detector.domain.ThreatAnalysis;
import java.util.List;

public class UrlCheckResponse {
    private String url;
    private boolean isPhishing;
    private double riskScore;
    private String riskLevel;
    private List<String> detectedThreats;
    private String recommendation;

    public UrlCheckResponse() {}

    public static UrlCheckResponse fromThreatAnalysis(ThreatAnalysis analysis) {
        UrlCheckResponse response = new UrlCheckResponse();
        response.url = analysis.getUrl();
        response.isPhishing = analysis.isPhishing();
        response.riskScore = analysis.getRiskScore();
        response.riskLevel = analysis.getRiskLevel().getLevel();
        response.detectedThreats = analysis.getDetectedThreats();
        response.recommendation = analysis.getRiskLevel().getRecommendation();
        return response;
    }

    // Getters and setters
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public boolean isPhishing() { return isPhishing; }
    public void setPhishing(boolean phishing) { isPhishing = phishing; }

    public double getRiskScore() { return riskScore; }
    public void setRiskScore(double riskScore) { this.riskScore = riskScore; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public List<String> getDetectedThreats() { return detectedThreats; }
    public void setDetectedThreats(List<String> detectedThreats) { this.detectedThreats = detectedThreats; }

    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
}
