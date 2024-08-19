package com.example.demo.ctl;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;


@RestController
public class Ctl {

    @RequestMapping("/test")
    public String test(HttpServletRequest request) {
        System.out.println("demo2 accessed!");
        return "这是demo2 /test";
    }
}
