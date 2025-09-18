package com.security.phishing_detector.domain;

public enum RiskLevel {
    SAFE("SAFE", "No significant phishing indicators detected."),
    LOW("LOW RISK", "Some suspicious indicators present. Proceed with caution."),
    MEDIUM("MEDIUM RISK", "Exercise extreme caution. Verify the URL source before visiting."),
    HIGH("HIGH RISK", "Do not visit this URL. It shows multiple signs of being a phishing attempt.");
    
    private final String level;
    private final String recommendation;
    
    RiskLevel(String level, String recommendation) {
        this.level = level;
        this.recommendation = recommendation;
    }
    
    public String getLevel() { return level; }
    public String getRecommendation() { return recommendation; }
    
    public static RiskLevel fromScore(double score) {
        if (score >= 80) return HIGH;
        if (score >= 50) return MEDIUM;
        if (score >= 20) return LOW;
        return SAFE;
    }
}