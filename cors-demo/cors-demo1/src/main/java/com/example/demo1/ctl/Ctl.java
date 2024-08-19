package com.example.demo1.ctl;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class Ctl {
    @RequestMapping("/test")
    public String test(HttpServletRequest request){
        System.out.println(request);
        return "这是demo1";
    }
}
