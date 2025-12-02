package com.korit.security_study.service;

import com.korit.security_study.dto.ApiRespDto;
import com.korit.security_study.dto.OAuth2MergeReqDto;
import com.korit.security_study.dto.OAuth2SignupReqDto;
import com.korit.security_study.entity.User;
import com.korit.security_study.entity.UserRole;
import com.korit.security_study.repository.OAuth2UserRepository;
import com.korit.security_study.repository.UserRepository;
import com.korit.security_study.repository.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

// oauth2로 회원가입 또는 연동
@Service
public class OAuth2AuthService {
    @Autowired
    private OAuth2UserRepository oAuth2UserRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public ApiRespDto<?> signup(OAuth2SignupReqDto oAuth2SignupReqDto) {
        Optional<User> foundUser = userRepository.getUserByEmail(oAuth2SignupReqDto.getEmail());
        if (foundUser.isPresent()) {
            return new ApiRespDto<>("failed", "이미 존재하는 이메일 입니다.", null);
        }

        Optional<User> foundUserByUsername = userRepository.getUserByUsername(oAuth2SignupReqDto.getUsername());
        if (foundUserByUsername.isPresent()) {
            return new ApiRespDto<>("failed", "이미 존재하는 username 입니다.", null);
        }

        Optional<User> optionalUser = userRepository.addUser(oAuth2SignupReqDto.toUserEntity(bCryptPasswordEncoder));
        if (optionalUser.isEmpty()) {
            return new ApiRespDto<>("failed", "회원 가입 실패", null);
        }

        User user = optionalUser.get();

        UserRole userRole = UserRole.builder()
                .userId(user.getUserId())
                .roleId(3)
                .build();
        userRoleRepository.addUserRole(userRole);

        oAuth2UserRepository.addOAuth2User(oAuth2SignupReqDto.toOAuth2UserEntity(user.getUserId()));

        return new ApiRespDto<>("success", oAuth2SignupReqDto.getProvider() + "로 회원 가입 성공", null);
    }

    public ApiRespDto<?> merge(OAuth2MergeReqDto oAuth2MergeReqDto) {
        Optional<User> foundUser = userRepository.getUserByUsername(oAuth2MergeReqDto.getUsername());
        if (foundUser.isEmpty()) {
            return new ApiRespDto<>("failed", "회원 정보가 잘못되었습니다", null);
        }

        if (!bCryptPasswordEncoder.matches(oAuth2MergeReqDto.getPassword(), foundUser.get().getPassword())) {
            return new ApiRespDto<>("failed", "회원 정보가 잘못되었습니다", null);
        }

        oAuth2UserRepository.addOAuth2User(oAuth2MergeReqDto.toEntity(foundUser.get().getUserId()));

        return new ApiRespDto<>("success", oAuth2MergeReqDto.getPassword()+" 연동 가입 완료", null);
    }
}
