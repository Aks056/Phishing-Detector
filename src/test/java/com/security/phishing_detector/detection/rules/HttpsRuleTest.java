package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HttpsRuleTest {

    private final HttpsRule httpsRule = new HttpsRule();

    @Test
    void testHttpsUrlReturnsSafe() {
        UrlInfo urlInfo = new UrlInfo("https://example.com");
        DetectionResult result = httpsRule.analyze(urlInfo);
        assertFalse(result.isThreatDetected());
        assertEquals(0.0, result.getRiskScore());
        assertNull(result.getThreatDescription());
    }

    @Test
    void testHttpUrlReturnsThreat() {
        UrlInfo urlInfo = new UrlInfo("http://example.com");
        DetectionResult result = httpsRule.analyze(urlInfo);
        assertTrue(result.isThreatDetected());
        assertEquals(10.0, result.getRiskScore());
        assertEquals("Not using secure HTTPS protocol", result.getThreatDescription());
    }
}