package com.security.phishing_detector;

import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class PhishingService {

    // ... (Your keyword and brand lists remain the same)
    private static final List<String> SUSPICIOUS_KEYWORDS = List.of(
            "login", "secure", "account", "update", "verify", "signin", "banking", "password"
    );
    private static final List<String> TARGETED_BRANDS = List.of(
            "paypal", "google", "facebook", "amazon", "apple", "netflix", "microsoft", "bank"
    );
    private static final Pattern IP_ADDRESS_PATTERN = Pattern.compile(
            "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");


    public AnalysisResult analyzeUrl(String url) {
        List<String> findings = new ArrayList<>();
        List<String> passedChecks = new ArrayList<>();

        // Rule 1: HTTPS Check
        if (!url.toLowerCase().startsWith("https://")) {
            findings.add("URL does not use a secure HTTPS connection.");
        } else {
            passedChecks.add("Uses a secure HTTPS connection.");
        }

        // Rule 2: IP Address Check
        try {
            String domain = url.split("/")[2];
            if (IP_ADDRESS_PATTERN.matcher(domain).find()) {
                findings.add("URL uses an IP address instead of a domain name.");
            } else {
                passedChecks.add("URL does not use an IP address.");
            }
        } catch (Exception e) {
            findings.add("URL is malformed or could not be parsed.");
        }

        // Rule 3: '@' Symbol Check
        if (url.substring(8).contains("@")) {
            findings.add("URL contains a suspicious '@' character, which can hide the true destination.");
        } else {
            passedChecks.add("URL does not contain a misleading '@' character.");
        }

        // Rule 4: Keyword Check
        boolean hasKeyword = SUSPICIOUS_KEYWORDS.stream().anyMatch(url.toLowerCase()::contains);
        boolean hasBrand = TARGETED_BRANDS.stream().anyMatch(url.toLowerCase()::contains);
        if (hasKeyword && hasBrand) {
            findings.add("URL contains a combination of suspicious keywords (e.g., 'login') and targeted brand names (e.g., 'paypal').");
        } else {
            passedChecks.add("URL does not contain a suspicious combination of keywords.");
        }

        // Final Decision: If there are any negative findings, it's phishing.
        if (!findings.isEmpty()) {
            return new AnalysisResult(true, findings);
        } else {
            return new AnalysisResult(false, passedChecks);
        }
    }
}