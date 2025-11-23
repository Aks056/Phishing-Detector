package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.domain.UrlInfo;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class KeywordDensityRule implements DetectionRule {

    private static final List<String> SUSPICIOUS_KEYWORDS = Arrays.asList(
        "login", "password", "bank", "account", "secure", "verify", "update", "confirm", "paypal", "amazon"
    );

    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        String url = urlInfo.getOriginalUrl().toLowerCase();
        long keywordCount = SUSPICIOUS_KEYWORDS.stream()
            .mapToLong(keyword -> countOccurrences(url, keyword))
            .sum();

        if (keywordCount > 2) {
            return new DetectionResult(true, Math.min(keywordCount * 5.0, 30.0), "High density of suspicious keywords in URL");
        }

        return new DetectionResult(false, 0.0, null);
    }

    private long countOccurrences(String text, String keyword) {
        long count = 0;
        int index = 0;
        while ((index = text.indexOf(keyword, index)) != -1) {
            count++;
            index += keyword.length();
        }
        return count;
    }
}