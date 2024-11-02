package example.oleevych.springsecurityjwtdemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/everyone")
    public String getPublicMessage() {
        return "Hello to everyone!";
    }

    @GetMapping("users")
    public String getSecuredMessage() {
        return "Hello to users!";
    }

    @GetMapping("admins")
    public String getAdminMessage() {
        return "Hello to admins!";
    }
}
