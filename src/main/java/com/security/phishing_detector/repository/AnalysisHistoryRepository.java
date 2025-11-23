package com.security.phishing_detector.repository;

import com.security.phishing_detector.domain.AnalysisHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AnalysisHistoryRepository extends JpaRepository<AnalysisHistory, Long> {

    List<AnalysisHistory> findTop10ByOrderByTimestampDesc();

    long countByIsThreatDetected(boolean isThreatDetected);

    List<AnalysisHistory> findByTimestampAfter(LocalDateTime timestamp);

    @Query("SELECT h FROM AnalysisHistory h WHERE h.timestamp BETWEEN :start AND :end")
    List<AnalysisHistory> findByTimestampBetween(@Param("start") LocalDateTime start, @Param("end") LocalDateTime end);

    @Query("SELECT h FROM AnalysisHistory h WHERE h.totalRiskScore BETWEEN :min AND :max")
    List<AnalysisHistory> findByTotalRiskScoreBetween(@Param("min") double min, @Param("max") double max);
}