package com.security.phishing_detector.detection.rules;


import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.springframework.stereotype.Component;

@Component
public class DomainLengthRule implements DetectionRule {
    private static final int MAX_NORMAL_DOMAIN_LENGTH = 50;

    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        if (urlInfo.getDomain().length() > MAX_NORMAL_DOMAIN_LENGTH) {
            return DetectionResult.threat(15.0, "Unusually long domain name");
        }
        return DetectionResult.safe();
    }
}