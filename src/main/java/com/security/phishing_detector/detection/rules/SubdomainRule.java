package com.security.phishing_detector.detection.rules;

import java.net.URI;

import org.springframework.stereotype.Component;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.domain.UrlInfo;

@Component
public class SubdomainRule implements DetectionRule {
    private static final int MAX_NORMAL_SUBDOMAINS = 4;

    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        try {
            String host = new URI(urlInfo.getOriginalUrl()).getHost();
            
            if (host == null) {
                return DetectionResult.safe();
            }
            
            // Count dots to detect multiple subdomains
            int dotCount = host.length() - host.replace(".", "").length();
            
            if (dotCount > 2) {
                return DetectionResult.threat(25.0, "Suspicious multiple subdomains detected");
            }
            
            // Also check for excessive number of subdomains
            String[] domainParts = host.split("\\.");
            if (domainParts.length > MAX_NORMAL_SUBDOMAINS) {
                return DetectionResult.threat(25.0, "Excessive number of subdomains");
            }
            
        } catch (Exception e) {
            // If URI parsing fails, fall back to domain-based check
            String[] domainParts = urlInfo.getDomain().split("\\.");
            if (domainParts.length > MAX_NORMAL_SUBDOMAINS) {
                return DetectionResult.threat(25.0, "Excessive number of subdomains");
            }
        }
        
        return DetectionResult.safe();
    }
}