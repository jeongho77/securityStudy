package com.cos.security1.config.auth;

import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

// 함수종료시 @AuthenticationPrincipla 어노테이션이 만들어진다.
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    private static final Logger log = LoggerFactory.getLogger(PrincipalOauth2UserService.class);

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private UserRepository userRepository;

    //구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    //userRequest: org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest@5acdf0c6
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        OAuth2UserInfo oAuth2UserInfo = null;
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            log.info("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            log.info("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            log.info("네이버 로그인 요청" + oAuth2User.getAttributes().get("response"));
            oAuth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
        }else{
            log.info("구글과 페이스북과 네이버만 지원");
        }

        log.info("userClientRegistration: " +userRequest.getClientRegistration().getRegistrationId()); //registrationId로 어떤 OAuth로 로그인했는지 확인 가능
        log.info("getAccessToken: " +userRequest.getAccessToken().getTokenValue());

        // 구글로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인을 완료 -> 코드를 리턴(oauth-client 라이브러리가) -> AccessToken요청
        // userRequest 정보 -> loadUser함수로 정보를 받음-> 회원프로필로 만듬
        log.info("User Attributes: " + oAuth2User.getAttributes());

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String userName = provider + "_" + providerId; //google_10123491293
        String password = bCryptPasswordEncoder.encode("겟인데어"); //사실 필요가없음 하지만 db에 넣어야하기때문에 형식아무거나!
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(userName);

        if(userEntity == null){
            log.info("OAuth 로그인이 최초 입니다.");
            userEntity = User.builder()
                    .username(userName)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }else {
            log.info("로그인을 한적이 있습니다.");
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}

