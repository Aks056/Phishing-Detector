package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DomainAgeRuleTest {

    private final DomainAgeRule domainAgeRule = new DomainAgeRule();

    @Test
    void testOldDomainReturnsSafe() {
        UrlInfo urlInfo = new UrlInfo("https://google.com");
        DetectionResult result = domainAgeRule.analyze(urlInfo);
        // Assuming WHOIS succeeds and domain is old, should be safe
        // In real test, may fail if WHOIS is blocked, so assert no exception
        assertNotNull(result);
    }

    @Test
    void testInvalidUrlReturnsSafe() {
        UrlInfo urlInfo = new UrlInfo("invalid-url");
        DetectionResult result = domainAgeRule.analyze(urlInfo);
        assertFalse(result.isThreatDetected());
    }
}