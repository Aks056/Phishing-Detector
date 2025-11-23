package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SslCertificateRuleTest {

    private final SslCertificateRule sslCertificateRule = new SslCertificateRule();

    @Test
    void testHttpsUrlReturnsSafe() {
        UrlInfo urlInfo = new UrlInfo("https://google.com");
        DetectionResult result = sslCertificateRule.analyze(urlInfo);
        // Assuming connection succeeds, should be safe
        assertFalse(result.isThreatDetected());
    }

    @Test
    void testHttpUrlReturnsThreat() {
        UrlInfo urlInfo = new UrlInfo("http://example.com");
        DetectionResult result = sslCertificateRule.analyze(urlInfo);
        assertTrue(result.isThreatDetected());
        assertEquals(15.0, result.getRiskScore());
        assertEquals("Not using secure HTTPS protocol", result.getThreatDescription());
    }

    @Test
    void testInvalidHttpsUrlReturnsThreat() {
        UrlInfo urlInfo = new UrlInfo("https://invalid-domain-that-does-not-exist.com");
        DetectionResult result = sslCertificateRule.analyze(urlInfo);
        assertTrue(result.isThreatDetected());
        assertTrue(result.getRiskScore() > 0);
    }
}