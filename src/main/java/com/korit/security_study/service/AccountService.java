package com.korit.security_study.service;

import com.korit.security_study.dto.ApiRespDto;
import com.korit.security_study.dto.DeleteUserReqDto;
import com.korit.security_study.dto.ModifyEmailReqDto;
import com.korit.security_study.dto.ModifyPasswordReqDto;
import com.korit.security_study.entity.User;
import com.korit.security_study.repository.UserRepository;
import com.korit.security_study.security.model.Principal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AccountService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public ApiRespDto<?> modifyPassword(ModifyPasswordReqDto modifyPasswordReqDto, Principal principal) {
        if (!principal.getUserId().equals(modifyPasswordReqDto.getUserId())) {
            return new ApiRespDto<>("failed", "잘못된 접근입니다.", null);
        }

        Optional<User> foundUser = userRepository.getUserByUserId(modifyPasswordReqDto.getUserId());

        if (foundUser.isEmpty()) {
            return new ApiRespDto<>("failed", "회원 정보가 일치하지 않습니다.", null);
        }

        User user = foundUser.get();

        if (!bCryptPasswordEncoder.matches(modifyPasswordReqDto.getOldPassword(), user.getPassword())) {
            return new ApiRespDto<>("failed", "회원 정보가 일치하지 않습니다.", null);
        }

        if (bCryptPasswordEncoder.matches(modifyPasswordReqDto.getNewPassword(), user.getPassword())) {
            return new ApiRespDto<>("failed", "동일한 비밀번호를 사용할 수 없습니다.", null);
        }

        int result = userRepository.modifyPassword(modifyPasswordReqDto.toEntity(bCryptPasswordEncoder));
        if (result != 1) {
            return new ApiRespDto<>("failed", "비밀번호 수정 실패", null);
        }

        return new ApiRespDto<>("success", "비밀번호 수정 성공", null);
    }

    public ApiRespDto<?> modifyEmail(ModifyEmailReqDto modifyEmailReqDto, Principal principal) {
        if (!principal.getUserId().equals(modifyEmailReqDto.getUserId())) {
            return new ApiRespDto<>("failed", "잘못된 접근입니다.", null);
        }

        Optional<User> foundUser = userRepository.getUserByUserId(modifyEmailReqDto.getUserId());

        if (foundUser.isEmpty()) {
            return new ApiRespDto<>("failed", "회원 정보를 찾을 수 없습니다.", null);
        }

        User user = foundUser.get();

        if (!bCryptPasswordEncoder.matches(modifyEmailReqDto.getPassword(), user.getPassword())) {
            return new ApiRespDto<>("failed", "회원 정보를 찾을 수 없습니다.", null);
        }

        int result = userRepository.modifyEmail(modifyEmailReqDto.toEntity());
        if (result != 1) {
            return new ApiRespDto<>("failed", "email 수정 실패", null);
        }

        return new ApiRespDto<>("success", "email 수정 성공", null);
    }

    public ApiRespDto<?> deleteUser(DeleteUserReqDto deleteUserReqDto, Principal principal) {
        if (!principal.getUserId().equals(deleteUserReqDto.getUserId())) {
            return new ApiRespDto<>("failed", "잘못된 접근입니다.", null);
        }

        Optional<User> foundUser = userRepository.getUserByUserId(deleteUserReqDto.getUserId());

        if (foundUser.isEmpty()) {
            return new ApiRespDto<>("failed", "회원 정보가 일치하지 않음", null);
        }

        User user = foundUser.get();

        if (!bCryptPasswordEncoder.matches(deleteUserReqDto.getPassword(), user.getPassword())) {
            return new ApiRespDto<>("failed", "회원 정보가 일치하지 않음", null);
        }

        int result = userRepository.deleteUserByUserId(deleteUserReqDto.getUserId());

        if (result != 1) {
            return new ApiRespDto<>("failed", "회원 정보 삭제 실패", null);
        }

        return new ApiRespDto<>("success", "회원 정보 삭제 완료", null);
    }
}
