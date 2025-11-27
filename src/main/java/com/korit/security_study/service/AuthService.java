package com.korit.security_study.service;

import com.korit.security_study.dto.ApiRespDto;
import com.korit.security_study.dto.DeleteUserReqDto;
import com.korit.security_study.dto.SigninReqDto;
import com.korit.security_study.dto.SignupReqDto;
import com.korit.security_study.entity.User;
import com.korit.security_study.entity.UserRole;
import com.korit.security_study.jwt.JwtUtils;
import com.korit.security_study.repository.UserRepository;
import com.korit.security_study.repository.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public ApiRespDto<?> addUser(SignupReqDto signupReqDto) {
        Optional<User> foundUser = userRepository.getUserByUsername(signupReqDto.getUsername());

        if (foundUser.isPresent()) {
            return new ApiRespDto<>("failed", "중복된 username", null);
        }

        Optional<User> optionalUser = userRepository.addUser(signupReqDto.toEntity(bCryptPasswordEncoder));
        if (optionalUser.isEmpty()) {
            return new ApiRespDto<>("failed", "회원 가입 실패", null);
        }

        UserRole userRole = UserRole.builder()
                .userId(optionalUser.get().getUserId())
                .roleId(3)
                .build();
        userRoleRepository.addUserRole(userRole);

        return new ApiRespDto<>("success", "회원 가입 완료", optionalUser.get());
    }

    public ApiRespDto<?> getUserByUsername(String username) {
        Optional<User> foundUser = userRepository.getUserByUsername(username);
        if (foundUser.isEmpty()) {
            return new ApiRespDto<>("failed", "조회된 회원 없음", null);
        }
        return new ApiRespDto<>("success", "단건 조회", foundUser.get());
    }

    public ApiRespDto<?> getUserByUserId(Integer userId) {
        Optional<User> foundUser = userRepository.getUserByUserId(userId);
        if (foundUser.isEmpty()) {
            return new ApiRespDto<>("failed", "조회된 회원 없음", null);
        }
        return new ApiRespDto<>("success", "단건 조회", foundUser.get());
    }

    public ApiRespDto<?> signin(SigninReqDto signinReqDto) {
        Optional<User> foundUser = userRepository.getUserByUsername(signinReqDto.getUsername());

        if (foundUser.isEmpty() ) {
            return new ApiRespDto<>("failed", "회원 정보가 일치하지 않음", null);
        }
        User user = foundUser.get();
        if (!bCryptPasswordEncoder.matches(signinReqDto.getPassword(), user.getPassword())) {
            return new ApiRespDto<>("failed", "회원 정보가 일치하지 않음", null);
        }

        String token = jwtUtils.generateAccessToken(user.getUserId().toString());

        return new ApiRespDto<>("success", "로그인 성공", token);
    }

    public ApiRespDto<?> deleteUser(DeleteUserReqDto deleteUserReqDto) {
        Optional<User> foundUser = userRepository.getUserByUsername(deleteUserReqDto.getUsername());

        if (foundUser.isEmpty() ||
                !bCryptPasswordEncoder.matches(deleteUserReqDto.getPassword(), foundUser.get().getPassword())) {
            return new ApiRespDto<>("failed", "회원 정보가 일치하지 않음", null);
        }

        int result = userRepository.deleteUserByUsername(deleteUserReqDto.getUsername());

        if (result != 1) {
            return new ApiRespDto<>("failed", "회원 정보 삭제 실패", null);
        }

        return new ApiRespDto<>("success", "회원 정보 삭제 완료", null);
    }
}
