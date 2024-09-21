package com.uou.security2.controller;

import com.uou.security2.model.User;
import com.uou.security2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

//@CrossOrigin
@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder; // JwtApplication에 IoC 등록해둔거 호출.

    @GetMapping("home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("token")
    public String token() {
        return "<h1>token</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("USER"); // 권한은 기본으로 USER로 설정합니다. ---> security 최신 버전에서는 권한 적용시 ROLE_ 쓰지 않음.
        userRepository.save(user);
        return "회원가입완료";
    }

    // user, manager, admin 권한이 접근 가능
    @GetMapping("/api/v1/manager")
    public String manager(){
        return "manager";
    }
    // manager, admin 권한이 접근 가능
    @GetMapping("/api/v1/admin")
    public String admin(){
        return "hi";
    }
    // admin 권한이 접근 가능
    @GetMapping("/api/v1/user")
    public String user(){
        return "user";
    }
}
