package com.security.phishing_detector.detection.rules;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.domain.UrlInfo;
import org.apache.commons.net.whois.WhoisClient;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class DomainAgeRule implements DetectionRule {

    private static final Pattern CREATION_DATE_PATTERN = Pattern.compile("Creation Date:\\s*([\\d-]+)", Pattern.CASE_INSENSITIVE);

    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        String domain = extractDomain(urlInfo.getOriginalUrl());
        if (domain == null) {
            return new DetectionResult(false, 0.0, null);
        }

        try {
            WhoisClient whois = new WhoisClient();
            whois.connect("whois.iana.org"); // Or specific TLD whois server
            String whoisData = whois.query(domain);
            whois.disconnect();

            Matcher matcher = CREATION_DATE_PATTERN.matcher(whoisData);
            if (matcher.find()) {
                String dateStr = matcher.group(1);
                LocalDate creationDate = LocalDate.parse(dateStr, DateTimeFormatter.ofPattern("yyyy-MM-dd"));
                long ageInDays = ChronoUnit.DAYS.between(creationDate, LocalDate.now());

                if (ageInDays < 365) { // Less than 1 year
                    return new DetectionResult(true, 20.0, "Domain is less than 1 year old");
                }
            }
        } catch (Exception e) {
            // If WHOIS fails, assume safe or low risk
            return new DetectionResult(false, 0.0, null);
        }

        return new DetectionResult(false, 0.0, null);
    }

    private String extractDomain(String url) {
        try {
            String domain = url.replaceFirst("https?://", "").split("/")[0];
            return domain;
        } catch (Exception e) {
            return null;
        }
    }
}