package com.api.rest.oauth.client_server.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("")
public class ClientController {

    @GetMapping("/hello")
    public ResponseEntity<String> hello(){
        return ResponseEntity.ok("Hello from the Client Server!");
    }

    @GetMapping("/authorized")
    public Map<String,String> authorized(@RequestParam String code) {
        return Collections.singletonMap("authorizationCode",code);
    }
}
