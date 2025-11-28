package com.korit.security_study.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class DeleteUserReqDto {
    private Integer userId;
    private String password;
}
