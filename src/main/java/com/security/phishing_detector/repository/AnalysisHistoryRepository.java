package com.security.phishing_detector.repository;

import com.security.phishing_detector.domain.AnalysisHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AnalysisHistoryRepository extends JpaRepository<AnalysisHistory, Long> {

    List<AnalysisHistory> findTop10ByOrderByTimestampDesc();
}