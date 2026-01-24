package com.security.phishing_detector.service;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.annotation.PostConstruct;

@Service
public class ThreatIntelligenceService {

    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    // Cache for known phishing URLs
    private final Set<String> phishingUrls = ConcurrentHashMap.newKeySet();
    private LocalDateTime lastUpdate = LocalDateTime.now();

    @Value("${phishtank.api.url:https://data.phishtank.com/data/online-valid.json}")
    private String phishtankUrl;

    @Value("${threat.intelligence.enabled:true}")
    private boolean enabled;

    public ThreatIntelligenceService(WebClient.Builder webClientBuilder, ObjectMapper objectMapper) {
        this.webClient = webClientBuilder.build();
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void init() {
        if (enabled) {
            try {
                updateThreatIntelligence();
            } catch (Exception e) {
                System.err.println("Failed to initialize threat intelligence on startup: " + e.getMessage());
                // Don't fail application startup due to threat intelligence issues
            }
        }
    }

    @Scheduled(fixedRate = 3600000) // Update every hour
    public void updateThreatIntelligence() {
        if (!enabled) return;

        try {
            String response = webClient.get()
                    .uri(phishtankUrl)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            if (response != null) {
                JsonNode root = objectMapper.readTree(response);
                Set<String> newUrls = new HashSet<>();

                for (JsonNode entry : root) {
                    String url = entry.get("url").asText();
                    if (url != null && !url.trim().isEmpty()) {
                        newUrls.add(url.toLowerCase().trim());
                    }
                }

                phishingUrls.clear();
                phishingUrls.addAll(newUrls);
                lastUpdate = LocalDateTime.now();

                System.out.println("Updated threat intelligence: " + phishingUrls.size() + " URLs loaded");
            }
        } catch (Exception e) {
            System.err.println("Failed to update threat intelligence: " + e.getMessage());
        }
    }

    public boolean isKnownPhishingUrl(String url) {
        if (!enabled || url == null) return false;
        return phishingUrls.contains(url.toLowerCase().trim());
    }

    public int getThreatDatabaseSize() {
        return phishingUrls.size();
    }

    public LocalDateTime getLastUpdate() {
        return lastUpdate;
    }

    public boolean isEnabled() {
        return enabled;
    }
}