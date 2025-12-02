package com.korit.security_study.repository;

import com.korit.security_study.entity.UserRole;
import com.korit.security_study.mapper.UserRoleMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Repository;

@Repository
public class UserRoleRepository {
    @Autowired
    private UserRoleMapper userRoleMapper;

    public void addUserRole(UserRole userRole) {
        try {
            userRoleMapper.addUserRole(userRole);
        } catch (DuplicateKeyException e) {
            e.printStackTrace();
        }
    }

    public int updateUserRole(UserRole userRole) {
        return userRoleMapper.updateUserRole(userRole);
    }
}
