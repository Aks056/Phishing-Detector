package com.security.phishing_detector;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class PhishingDetectorApplication {

	public static void main(String[] args) {
		SpringApplication.run(PhishingDetectorApplication.class, args);
	}

}
