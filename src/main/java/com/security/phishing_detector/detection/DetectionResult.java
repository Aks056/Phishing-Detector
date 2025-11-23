package com.security.phishing_detector.detection;

import jakarta.persistence.Embeddable;

@Embeddable
public class DetectionResult {
    private boolean threatDetected;
    private double riskScore;
    private String threatDescription;

    public DetectionResult() {}

    public DetectionResult(boolean threatDetected, double riskScore, String threatDescription) {
        this.threatDetected = threatDetected;
        this.riskScore = riskScore;
        this.threatDescription = threatDescription;
    }

    public boolean isThreatDetected() { return threatDetected; }
    public void setThreatDetected(boolean threatDetected) { this.threatDetected = threatDetected; }

    public double getRiskScore() { return riskScore; }
    public void setRiskScore(double riskScore) { this.riskScore = riskScore; }

    public String getThreatDescription() { return threatDescription; }
    public void setThreatDescription(String threatDescription) { this.threatDescription = threatDescription; }

    public static DetectionResult safe() {
        return new DetectionResult(false, 0.0, null);
    }

    public static DetectionResult threat(double riskScore, String description) {
        return new DetectionResult(true, riskScore, description);
    }
}