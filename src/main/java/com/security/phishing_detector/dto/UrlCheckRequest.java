package com.security.phishing_detector.dto;

import jakarta.validation.constraints.NotBlank;

public class UrlCheckRequest {
    @NotBlank(message = "URL cannot be blank")
    private String url;

    public UrlCheckRequest() {}

    public UrlCheckRequest(String url) {
        this.url = url;
    }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
}