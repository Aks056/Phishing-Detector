package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.springframework.stereotype.Component;
import java.util.regex.Pattern;

@Component
public class IpAddressRule implements DetectionRule {
    private static final Pattern IP_PATTERN = Pattern.compile(
        "^https?://(?:\\d{1,3}\\.){3}\\d{1,3}"
    );
    
    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        if (IP_PATTERN.matcher(urlInfo.getOriginalUrl()).find()) {
            return DetectionResult.threat(30.0, "Uses IP address instead of domain name");
        }
        return DetectionResult.safe();
    }
}