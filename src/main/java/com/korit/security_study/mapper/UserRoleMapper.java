package com.korit.security_study.mapper;

import com.korit.security_study.entity.UserRole;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserRoleMapper {
    int addUserRole(UserRole userRole);
    int updateUserRole(UserRole userRole);
}
