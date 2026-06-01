package com.backend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/demo")
public class DemoController {

    @GetMapping
    public Map<String, Object> hello() {
        return Map.of(
            "message", "Hello World! You have successfully accessed this protected endpoint.",
            "timestamp", LocalDateTime.now().toString(),
            "status", "Authorized",
            "info", "This resource requires a valid, unexpired Access Token in the Authorization header."
        );
    }
}
