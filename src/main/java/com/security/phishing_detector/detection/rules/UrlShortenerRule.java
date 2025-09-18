package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.springframework.stereotype.Component;
import java.util.Set;

@Component
public class UrlShortenerRule implements DetectionRule {
    private static final Set<String> SHORTENER_DOMAINS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
            "is.gd", "buff.ly", "adf.ly", "tiny.cc"
    );

    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        if (SHORTENER_DOMAINS.contains(urlInfo.getDomain())) {
            return DetectionResult.threat(20.0, "Uses URL shortener service");
        }
        return DetectionResult.safe();
    }
}