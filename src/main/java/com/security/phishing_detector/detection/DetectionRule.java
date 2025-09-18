package com.security.phishing_detector.detection;

import com.security.phishing_detector.domain.UrlInfo;

public interface DetectionRule {
    DetectionResult analyze(UrlInfo urlInfo);
}