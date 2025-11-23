package com.security.phishing_detector;

import java.util.List;

/**
 * @deprecated Replaced by `com.security.phishing_detector.domain.ThreatAnalysis`.
 * This class remains for backward compatibility and should not be used in new code.
 */
@Deprecated
public class AnalysisResult {
    private final boolean isPhishing;
    private final List<String> reasons;

    public AnalysisResult(boolean isPhishing, List<String> reasons) {
        this.isPhishing = isPhishing;
        this.reasons = reasons;
    }

    @Deprecated
    public boolean isPhishing() {
        return isPhishing;
    }

    @Deprecated
    public List<String> getReasons() {
        return reasons;
    }
}