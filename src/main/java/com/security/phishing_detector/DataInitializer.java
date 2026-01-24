package com.security.phishing_detector;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import com.security.phishing_detector.domain.AnalysisHistory;
import com.security.phishing_detector.detection.DetectionResult;
import com.security.phishing_detector.repository.AnalysisHistoryRepository;

@Component
public class DataInitializer implements CommandLineRunner {

    private final AnalysisHistoryRepository historyRepository;

    public DataInitializer(AnalysisHistoryRepository historyRepository) {
        this.historyRepository = historyRepository;
    }

    @Override
    public void run(String... args) throws Exception {
        System.out.println("DataInitializer: Checking if database needs initialization...");
        if (historyRepository.count() == 0) {
            System.out.println("DataInitializer: Database is empty, adding sample data...");
            // Add sample analysis data for dashboard
            createSampleData();
            System.out.println("DataInitializer: Sample data added successfully. Total records: " + historyRepository.count());
        } else {
            System.out.println("DataInitializer: Database already has data, skipping initialization.");
        }
    }

    private void createSampleData() {
        LocalDateTime now = LocalDateTime.now();

        // Sample safe URLs
        List<String> safeUrls = Arrays.asList(
            "https://www.google.com",
            "https://github.com",
            "https://stackoverflow.com",
            "https://www.microsoft.com",
            "https://www.amazon.com"
        );

        // Sample phishing URLs
        List<String> phishingUrls = Arrays.asList(
            "https://secure-bank-login.com",
            "https://paypal-verify-account.net",
            "https://amazon-order-update.ru",
            "https://netflix-account-fix.cn",
            "https://microsoft-support-help.info"
        );

        // Add safe analyses
        for (String url : safeUrls) {
            AnalysisHistory history = new AnalysisHistory();
            history.setUrl(url);
            history.setTimestamp(now.minusDays((int)(Math.random() * 7)));
            history.setThreatDetected(false);
            history.setTotalRiskScore(Math.random() * 25); // Low risk
            history.setResults(new ArrayList<>()); // Initialize the list

            DetectionResult result = new DetectionResult();
            result.setThreatDetected(false);
            result.setRiskScore(5.0);
            result.setThreatDescription("Domain appears legitimate");
            history.getResults().add(result);

            historyRepository.save(history);
        }

        // Add phishing analyses
        for (String url : phishingUrls) {
            AnalysisHistory history = new AnalysisHistory();
            history.setUrl(url);
            history.setTimestamp(now.minusDays((int)(Math.random() * 7)));
            history.setThreatDetected(true);
            history.setTotalRiskScore(60 + Math.random() * 40); // Medium to high risk
            history.setResults(new ArrayList<>()); // Initialize the list

            DetectionResult result1 = new DetectionResult();
            result1.setThreatDetected(true);
            result1.setRiskScore(30.0);
            result1.setThreatDescription("URL contains suspicious keywords");
            history.getResults().add(result1);

            DetectionResult result2 = new DetectionResult();
            result2.setThreatDetected(true);
            result2.setRiskScore(25.0);
            result2.setThreatDescription("Domain is very new or suspicious");
            history.getResults().add(result2);

            historyRepository.save(history);
        }

        // Add some recent analyses (last 24 hours)
        for (int i = 0; i < 5; i++) {
            AnalysisHistory history = new AnalysisHistory();
            history.setUrl("https://example" + i + ".com");
            history.setTimestamp(now.minusHours(i * 4));
            history.setThreatDetected(i % 2 == 0);
            history.setTotalRiskScore(i % 2 == 0 ? 80.0 : 15.0);
            history.setResults(new ArrayList<>()); // Initialize the list

            DetectionResult result = new DetectionResult();
            result.setThreatDetected(i % 2 == 0);
            result.setRiskScore(i % 2 == 0 ? 40.0 : 10.0);
            result.setThreatDescription(i % 2 == 0 ? "Potential phishing indicators detected" : "URL appears safe");
            history.getResults().add(result);

            historyRepository.save(history);
        }
    }
}