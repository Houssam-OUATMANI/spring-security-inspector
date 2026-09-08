package com.example.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    @GetMapping("/admin/data")
    @PreAuthorize("hasRole('ADMIN')")
    public String getAdminData() {
        return "classified";
    }

    @GetMapping("/user/profile")
    @PreAuthorize("hasAuthority('SCOPE_profile')")
    public String getUserProfile() {
        return "profile";
    }
}
