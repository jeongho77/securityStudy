package com.cos.security1.config.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    private static final Logger log = LoggerFactory.getLogger(PrincipalOauth2UserService.class);

    //구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    //userRequest: org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest@5acdf0c6
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("userClientRegistration: " +userRequest.getClientRegistration());
        log.info("getAccessToken: " +userRequest.getAccessToken().getTokenValue());
        // Load the user details from the OAuth2 provider
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Log entire user attributes
        log.info("User Attributes: " + oAuth2User.getAttributes().toString());
        return super.loadUser(userRequest);
    }
}
