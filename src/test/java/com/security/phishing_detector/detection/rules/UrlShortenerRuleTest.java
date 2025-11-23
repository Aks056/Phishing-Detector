package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class UrlShortenerRuleTest {

    private final UrlShortenerRule urlShortenerRule = new UrlShortenerRule();

    @Test
    void testShortenerDomainReturnsThreat() {
        UrlInfo urlInfo = new UrlInfo("https://bit.ly/abc");
        DetectionResult result = urlShortenerRule.analyze(urlInfo);
        assertTrue(result.isThreatDetected());
        assertEquals(20.0, result.getRiskScore());
        assertEquals("Uses URL shortener service", result.getThreatDescription());
    }

    @Test
    void testNonShortenerDomainReturnsSafe() {
        UrlInfo urlInfo = new UrlInfo("https://example.com");
        DetectionResult result = urlShortenerRule.analyze(urlInfo);
        assertFalse(result.isThreatDetected());
        assertEquals(0.0, result.getRiskScore());
        assertNull(result.getThreatDescription());
    }
}