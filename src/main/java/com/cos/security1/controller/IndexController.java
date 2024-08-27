package com.cos.security1.controller;

import ch.qos.logback.core.model.Model;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.aspectj.weaver.bcel.BcelAnnotation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {

    private static final Logger log = LoggerFactory.getLogger(IndexController.class);
    private final UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public IndexController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    //localhost:8080/
    //localhost:8080
    @GetMapping({"","/"})
    public String index(){
        //머스테치 기본폴더 src/main/resources/
        //뷰리졸버 설정 : templates(prefix) , .mustache(suffix)
        return "index"; // src/main/resources/templates/index.mustache경로로 찾는다.
    }

    @GetMapping("/user")
    public @ResponseBody String user(){
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    //회원가입
    @PostMapping("/join")
    public String join(User user) {
        log.info(String.valueOf(user));
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER')or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data() {
        return "데이터정보";
    }
}
