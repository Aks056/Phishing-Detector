package com.security.phishing_detector.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;

@Configuration
@Profile("production")
public class ProductionSecurityConfig {

    @Bean
    public HttpFirewall httpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();

        // Allow common characters but block suspicious ones
        firewall.setAllowUrlEncodedSlash(true);
        firewall.setAllowUrlEncodedPercent(true);
        firewall.setAllowBackSlash(true);
        firewall.setAllowUrlEncodedPeriod(true);

        // Block suspicious characters that could be used in attacks
        firewall.setAllowSemicolon(true); // Allow semicolons for matrix parameters
        firewall.setAllowUrlEncodedCarriageReturn(false);
        firewall.setAllowUrlEncodedLineFeed(false);

        return firewall;
    }
}