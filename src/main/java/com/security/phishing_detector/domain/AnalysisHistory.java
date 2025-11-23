package com.security.phishing_detector.domain;

import com.security.phishing_detector.detection.DetectionResult;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "analysis_history")
public class AnalysisHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String url;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(nullable = false)
    private boolean isThreatDetected;

    @Column(nullable = false)
    private double totalRiskScore;

    @ElementCollection
    @CollectionTable(name = "analysis_results", joinColumns = @JoinColumn(name = "history_id"))
    private List<DetectionResult> results;

    // Constructors
    public AnalysisHistory() {}

    public AnalysisHistory(String url, boolean isThreatDetected, double totalRiskScore, List<DetectionResult> results) {
        this.url = url;
        this.timestamp = LocalDateTime.now();
        this.isThreatDetected = isThreatDetected;
        this.totalRiskScore = totalRiskScore;
        this.results = results;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }

    public boolean isThreatDetected() { return isThreatDetected; }
    public void setThreatDetected(boolean threatDetected) { isThreatDetected = threatDetected; }

    public double getTotalRiskScore() { return totalRiskScore; }
    public void setTotalRiskScore(double totalRiskScore) { this.totalRiskScore = totalRiskScore; }

    public List<DetectionResult> getResults() { return results; }
    public void setResults(List<DetectionResult> results) { this.results = results; }
}