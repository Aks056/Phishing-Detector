package com.security.phishing_detector;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class PhishingController {

    private final PhishingService phishingService;

    @Autowired
    public PhishingController(PhishingService phishingService) {
        this.phishingService = phishingService;
    }

    @PostMapping("/check-url")
    public String checkUrl(@RequestParam("url_to_check") String url, Model model) {
        AnalysisResult result = phishingService.analyzeUrl(url);

        // Pass the entire list of reasons to the template
        model.addAttribute("reasons", result.getReasons()); // Note the key is "reasons"
        model.addAttribute("isPhishing", result.isPhishing());
        model.addAttribute("checkedUrl", url); // Also pass the original URL for context

        return "result";
    }
}