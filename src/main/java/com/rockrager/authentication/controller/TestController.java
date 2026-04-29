package com.rockrager.authentication.controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/test")
    public String testApi(){
        return "Rockrangerz Spring Boot Docker Test Successful";
    }
}