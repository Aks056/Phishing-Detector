package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.springframework.stereotype.Component;

@Component
public class HttpsRule implements DetectionRule {
    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        if (!urlInfo.isHttps()) {
            return DetectionResult.threat(10.0, "Not using secure HTTPS protocol");
        }
        return DetectionResult.safe();
    }
}