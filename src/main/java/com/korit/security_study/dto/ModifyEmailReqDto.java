package com.korit.security_study.dto;

import com.korit.security_study.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Data
@AllArgsConstructor
public class ModifyEmailReqDto {
    private Integer userId;
    private String password;
    private String email;

    public User toEntity() {
        return User.builder()
                .userId(userId)
                .email(email)
                .build();
    }
}
