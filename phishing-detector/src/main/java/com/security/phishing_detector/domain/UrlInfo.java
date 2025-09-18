package com.security.phishing_detector.domain;


import java.net.URL;

public class UrlInfo {
    private final String originalUrl;
    private final String domain;
    private final String path;
    private final String query;
    private final boolean isValid;
    
      public UrlInfo(String url) {
        this.originalUrl = url;
        URL parsedUrl = null;
        boolean valid = true;

        try {
            parsedUrl = new java.net.URI(url).toURL();
        } catch (Exception e) {
            valid = false;
        }

        this.isValid = valid;
        if (valid && parsedUrl != null) {
            this.domain = parsedUrl.getHost() != null ? parsedUrl.getHost().toLowerCase() : "";
            this.path = parsedUrl.getPath() != null ? parsedUrl.getPath().toLowerCase() : "";
            this.query = parsedUrl.getQuery() != null ? parsedUrl.getQuery().toLowerCase() : "";
        } else {
            this.domain = "";
            this.path = "";
            this.query = "";
        }
    }
    
    public String getOriginalUrl() { return originalUrl; }
    public String getDomain() { return domain; }
    public String getPath() { return path; }
    public String getQuery() { return query; }
    public boolean isValid() { return isValid; }
    public boolean isHttps() { return originalUrl.startsWith("https://"); }
}