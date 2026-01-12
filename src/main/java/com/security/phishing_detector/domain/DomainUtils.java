package com.security.phishing_detector.domain;

import java.net.URI;

public class DomainUtils {

    public static String extractMainDomain(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost(); // secure.google.account-check.net

            if (host == null) return "";

            String[] parts = host.split("\\.");

            if (parts.length < 2) return host;

            // last two parts → account-check.net
            return parts[parts.length - 2] + "." + parts[parts.length - 1];

        } catch (Exception e) {
            return "";
        }
    }
}
