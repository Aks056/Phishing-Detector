package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.domain.UrlInfo;
import org.springframework.stereotype.Component;

@Component
public class TyposquattingRule implements DetectionRule {
    private static final String[] POPULAR_DOMAINS = {
            "google.com", "facebook.com", "amazon.com", "microsoft.com",
            "apple.com", "paypal.com", "ebay.com", "netflix.com",
            "instagram.com", "twitter.com", "linkedin.com", "github.com"
    };

    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        String domain = urlInfo.getDomain();

        for (String popular : POPULAR_DOMAINS) {
            if (domain.contains(popular.replace(".com", "")) && !domain.equals(popular)) {
                if (calculateEditDistance(domain, popular) <= 2) {
                    return DetectionResult.threat(35.0, "Possible typosquatting of popular domain");
                }
            }
        }
        return DetectionResult.safe();
    }

    private int calculateEditDistance(String s1, String s2) {
        int[][] dp = new int[s1.length() + 1][s2.length() + 1];

        for (int i = 0; i <= s1.length(); i++) {
            for (int j = 0; j <= s2.length(); j++) {
                if (i == 0) {
                    dp[i][j] = j;
                } else if (j == 0) {
                    dp[i][j] = i;
                } else {
                    dp[i][j] = Math.min(
                            dp[i-1][j-1] + (s1.charAt(i-1) == s2.charAt(j-1) ? 0 : 1),
                            Math.min(dp[i-1][j] + 1, dp[i][j-1] + 1)
                    );
                }
            }
        }
        return dp[s1.length()][s2.length()];
    }
}