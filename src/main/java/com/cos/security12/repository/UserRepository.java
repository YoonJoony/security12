package com.cos.security12.repository;

import com.cos.security12.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository // 안붙여도 된다.
public interface UserRepository extends JpaRepository<User, Integer> {
    // select *from user where username = 1?
    public User findByUsername(String username);
}
