package com.cos.security12.config.auth;

import com.cos.security12.model.User;
import com.cos.security12.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 loginProcessUrl("/login") 요청이 오면
// 자동으로 UserDetailsService 타입으로 IoC 되어있는 loadUserByUsername() 함수가 실행됨.
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    // loginProcessUrl("/login")에서 넘어온 username이 아래 매개변수에 대입됨.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        // 유저가 있으면 시큐리티 session안에 들어갈 Authentication 인증 객체 안에 들어감.
        // Security Session <- Authentication <- PrincipalDetails(UserDetail)
        if(user != null) {
          return new PrincipalDetails(user); //User 타입을, UserDetails를 상속받는 PrincipalDetailsService 객체로 변환하여 리턴
        }
        return null;
    }
}
