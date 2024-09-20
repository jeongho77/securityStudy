package com.uou.security2.config.auth;

import com.uou.security2.model.User;
import com.uou.security2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // 시큐리티 session = Authentication = UserDetails
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("principalDetailsService의 loadUserByUsername()");
        User userEntity = userRepository.findByUsername(username);

        System.out.println("userEntity : " + userEntity);

//        if (userEntity != null) {
//            return new PrincipalDetails(userEntity);
//        }
        return new PrincipalDetails(userEntity);
    }

}
