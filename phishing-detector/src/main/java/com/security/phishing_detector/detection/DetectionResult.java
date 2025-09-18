package com.security.phishing_detector.detection;

public class DetectionResult {
    private final boolean threatDetected;
    private final double riskScore;
    private final String threatDescription;
    
    public DetectionResult(boolean threatDetected, double riskScore, String threatDescription) {
        this.threatDetected = threatDetected;
        this.riskScore = riskScore;
        this.threatDescription = threatDescription;
    }
    
    public boolean isThreatDetected() { return threatDetected; }
    public double getRiskScore() { return riskScore; }
    public String getThreatDescription() { return threatDescription; }
    
    public static DetectionResult safe() {
        return new DetectionResult(false, 0.0, null);
    }
    
    public static DetectionResult threat(double score, String description) {
        return new DetectionResult(true, score, description);
    }
}