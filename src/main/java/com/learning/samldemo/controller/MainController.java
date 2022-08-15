package com.learning.samldemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class MainController {

    @GetMapping("/")
    public String showWelcomePage(Model model){
        return "index";
    }

    @GetMapping("/handleAuthSuccess")
    public String handleAuth(Model model){
        model.addAttribute("Test","Test");
        return "index";
    }

    @GetMapping("/logoutSuccess")
    public String handleLogout(Model model){
        model.addAttribute("Test","Test");
        return "logout";
    }
}
