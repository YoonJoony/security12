package com.cos.security12.config;

import com.cos.security12.config.oauth.PrincipalOAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터 체인에 등록이 된다.
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured... : 컨트롤러에 단일 권한 접속 허가
                                                                    // prePost... : 컨트롤러에 다중 권한 접속 허가
public class SecurityConfig {

    @Autowired
    private PrincipalOAuth2UserService principalOAuth2UserService;
    // 패스워드 인코딩(암호화)
    @Bean
    public BCryptPasswordEncoder encoderPwd() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(CsrfConfigurer::disable)
            .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/user/**").authenticated()
                    .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                    .requestMatchers("/admin/**").hasAnyRole("ADMIN")
                    .anyRequest().permitAll()

            )
            .formLogin((form) ->  form       // 폼 로그인을 사용하며, 로그인 페이지와 관련된 설정을 함.
                    .loginPage("/loginForm") // 인증이 필요한 페이지에 대한 모든 접근은 해당 페이지로 리다이렉트 된다.
                    .permitAll()             // 모든 사용자가 로그인 페이지에 접근할 수 있도록 한다.
                    .loginProcessingUrl("/login") // 시큐리티가 이 주소를 낚아채서 대신 로그인을 진행한다.
                    .defaultSuccessUrl("/")  // 로그인 완료 시 기본 주소
            )
            .oauth2Login((oauth2) -> oauth2  // oauth2 로그인 활성화
                .loginPage("/loginForm")     // 로그인 후 후처리 -> 코드 받기 -> 엑세스토큰 -> 프로필 정보 가져오기 -> 회원가입
                .userInfoEndpoint(userInfoEndpointConfig ->
                        userInfoEndpointConfig.userService(principalOAuth2UserService))
            );
        return http.build();
    }
}
