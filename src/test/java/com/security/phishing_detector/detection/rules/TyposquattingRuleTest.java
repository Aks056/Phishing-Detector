package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TyposquattingRuleTest {

    private final TyposquattingRule typosquattingRule = new TyposquattingRule();

    @Test
    void testExactMatchReturnsSafe() {
        UrlInfo urlInfo = new UrlInfo("https://google.com");
        DetectionResult result = typosquattingRule.analyze(urlInfo);
        assertFalse(result.isThreatDetected());
    }

    @Test
    void testCloseMatchReturnsThreat() {
        UrlInfo urlInfo = new UrlInfo("https://g00gle.com");
        DetectionResult result = typosquattingRule.analyze(urlInfo);
        assertTrue(result.isThreatDetected());
        assertEquals(35.0, result.getRiskScore());
        assertEquals("Possible typosquatting of popular domain", result.getThreatDescription());
    }

    @Test
    void testNoMatchReturnsSafe() {
        UrlInfo urlInfo = new UrlInfo("https://randomsite.com");
        DetectionResult result = typosquattingRule.analyze(urlInfo);
        assertFalse(result.isThreatDetected());
    }
}