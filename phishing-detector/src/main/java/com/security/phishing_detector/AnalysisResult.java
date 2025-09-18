package com.security.phishing_detector;

import java.util.List;

public class AnalysisResult {
    private final boolean isPhishing;
    private final List<String> reasons; // Changed from String to List<String>

    public AnalysisResult(boolean isPhishing, List<String> reasons) {
        this.isPhishing = isPhishing;
        this.reasons = reasons;
    }

    public boolean isPhishing() {
        return isPhishing;
    }

    public List<String> getReasons() { // Changed getter name
        return reasons;
    }
}