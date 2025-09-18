package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.springframework.stereotype.Component;
import java.util.Arrays;
import java.util.Set;

@Component
public class KeywordRule implements DetectionRule {
    private static final Set<String> PHISHING_KEYWORDS = Set.of(
            "verify", "suspend", "urgent", "immediate", "confirm", "update",
            "secure", "account", "bank", "paypal", "amazon", "microsoft",
            "google", "apple", "login", "signin", "click", "here"
    );

    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        String fullUrl = (urlInfo.getOriginalUrl() + " " + urlInfo.getPath() + " " + urlInfo.getQuery()).toLowerCase();

        long keywordCount = PHISHING_KEYWORDS.stream()
                .mapToLong(keyword -> countOccurrences(fullUrl, keyword))
                .sum();

        if (keywordCount > 2) {
            double score = keywordCount * 5;
            return DetectionResult.threat(score, "Contains multiple phishing-related keywords");
        }
        return DetectionResult.safe();
    }

    private long countOccurrences(String text, String pattern) {
        return Arrays.stream(text.split(" "))
                .mapToLong(word -> word.contains(pattern) ? 1 : 0)
                .sum();
    }
}