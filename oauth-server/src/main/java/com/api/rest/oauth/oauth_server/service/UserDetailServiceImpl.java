package com.api.rest.oauth.oauth_server.service;

import com.api.rest.oauth.oauth_server.persistence.entities.User;
import com.api.rest.oauth.oauth_server.persistence.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserDetailServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new IllegalArgumentException("El usuario "+ username + " no existe."));

        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        // Agregar roles con prefijo ROLE_
        user.getRoles().forEach(role ->
                authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name()))));

        // Agregar permisos individuales
        user.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .forEach(permission ->
                        authorityList.add(new SimpleGrantedAuthority(permission.getPermissionName())));

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.isEnabled(),
                user.isAccountNoExpired(),
                user.isCredentialsNonExpired(),
                user.isAccountNonLocked(),
                authorityList
        );
    }
}
