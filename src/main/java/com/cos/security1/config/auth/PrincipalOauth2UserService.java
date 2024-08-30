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
        log.info("userClientRegistration: " +userRequest.getClientRegistration()); //registrationId로 어떤 OAuth로 로그인했는지 확인 가능
        log.info("getAccessToken: " +userRequest.getAccessToken().getTokenValue());
        // Load the user details from the OAuth2 provider
        // 구글로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인을 완료 -> 코드를 리턴(oauth-client 라이브러리가) -> AccessToken요청
        // userRequest 정보 -> loadUser함수로 정보를 받음-> 회원프로필로 만듬
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Log entire user attributes
        log.info("User Attributes: " + oAuth2User.getAttributes().toString());
        return super.loadUser(userRequest);
    }
}
