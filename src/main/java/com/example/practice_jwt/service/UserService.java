package com.example.practice_jwt.service;

import com.example.practice_jwt.dto.UserDto;
import com.example.practice_jwt.entity.Authority;
import com.example.practice_jwt.entity.User;
import com.example.practice_jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.security.SecurityUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Security;
import java.util.Collections;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserServie {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        // 가입되어 있는 회원인 경우 권한 정보 만들고
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();
        // 유저 정보 만들어서 save
        User user = User.builder()
                .username(userDto.getUsername())
                .password(userDto.getPassword())
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return userRepository.save(user);
    }

    // 유저 정보 가져오는 메서드
    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    // 현재 securityContext에 저장된 username의 정보만 가져오는 메서드
    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername()
                .flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}
