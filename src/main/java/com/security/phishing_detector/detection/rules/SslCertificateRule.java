package com.security.phishing_detector.detection.rules;

import java.net.URI;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

import org.springframework.stereotype.Component;

import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.detection.DetectionRule;
import com.security.phishing_detector.domain.UrlInfo;

@Component
public class SslCertificateRule implements DetectionRule {

    @Override
    public DetectionResult analyze(UrlInfo urlInfo) {
        String url = urlInfo.getOriginalUrl();
        if (!url.startsWith("https://")) {
            return new DetectionResult(true, 15.0, "Not using secure HTTPS protocol");
        }

        try {
            URI httpsUri = URI.create(url);
            URL httpsUrl = httpsUri.toURL();
            HttpsURLConnection connection = (HttpsURLConnection) httpsUrl.openConnection();
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.connect();

            // Check if certificate is valid (basic check)
            if (connection.getServerCertificates() == null || connection.getServerCertificates().length == 0) {
                return new DetectionResult(true, 20.0, "No SSL certificate found");
            }

            // Could check expiry, but for simplicity, assume valid if connected
            return new DetectionResult(false, 0.0, null);
        } catch (Exception e) {
            return new DetectionResult(true, 25.0, "SSL certificate validation failed: " + e.getMessage());
        }
    }
}