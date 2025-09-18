package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.springframework.stereotype.Component;

@Component
public class SubdomainRule implements DetectionRule {
    private static final int MAX_NORMAL_SUBDOMAINS = 4;

    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        String[] domainParts = urlInfo.getDomain().split("\\.");
        if (domainParts.length > MAX_NORMAL_SUBDOMAINS) {
            return DetectionResult.threat(25.0, "Excessive number of subdomains");
        }
        return DetectionResult.safe();
    }
}