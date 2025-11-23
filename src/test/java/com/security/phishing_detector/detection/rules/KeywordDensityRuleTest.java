package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class KeywordDensityRuleTest {

    private final KeywordDensityRule keywordDensityRule = new KeywordDensityRule();

    @Test
    void testLowKeywordDensityReturnsSafe() {
        UrlInfo urlInfo = new UrlInfo("https://example.com");
        DetectionResult result = keywordDensityRule.analyze(urlInfo);
        assertFalse(result.isThreatDetected());
    }

    @Test
    void testHighKeywordDensityReturnsThreat() {
        UrlInfo urlInfo = new UrlInfo("https://login-bank-secure-update.com");
        DetectionResult result = keywordDensityRule.analyze(urlInfo);
        assertTrue(result.isThreatDetected());
        assertTrue(result.getRiskScore() > 0);
        assertEquals("High density of suspicious keywords in URL", result.getThreatDescription());
    }

    @Test
    void testMediumKeywordDensityReturnsSafe() {
        UrlInfo urlInfo = new UrlInfo("https://bank.com/login");
        DetectionResult result = keywordDensityRule.analyze(urlInfo);
        assertFalse(result.isThreatDetected());
    }
}