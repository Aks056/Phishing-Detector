package com.security.phishing_detector;

/**
 * @deprecated Use `com.security.phishing_detector.service.PhishingAnalysisService` (modular rule engine) instead.
 * This class remains as a compatibility placeholder and intentionally throws if invoked.
 */
@Deprecated
public class PhishingService {

    /**
     * Deprecated. Do not call — use PhishingAnalysisService.analyzeUrl instead.
     */
    @Deprecated
    public AnalysisResult analyzeUrl(String url) {
        throw new UnsupportedOperationException("PhishingService is deprecated. Use com.security.phishing_detector.service.PhishingAnalysisService instead.");
    }
}