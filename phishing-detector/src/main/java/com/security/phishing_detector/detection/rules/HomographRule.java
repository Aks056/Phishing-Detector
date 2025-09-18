package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.springframework.stereotype.Component;
import java.util.regex.Pattern;

@Component
public class HomographRule implements DetectionRule {
    private static final Pattern SUSPICIOUS_CHAR_PATTERN = Pattern.compile(
            "[а-яё]|[αβγδεζηθικλμνξοπρστυφχψω]|[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ]"
    );

    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        if (SUSPICIOUS_CHAR_PATTERN.matcher(urlInfo.getDomain()).find()) {
            return DetectionResult.threat(40.0, "Contains suspicious characters (possible homograph attack)");
        }
        return DetectionResult.safe();
    }
}