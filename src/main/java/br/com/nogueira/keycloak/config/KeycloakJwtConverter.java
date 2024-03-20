package br.com.nogueira.keycloak.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.Map;

public class KeycloakJwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Map<String, Collection<String>> realmAccess = jwt.getClaim("realm_access");
        var roles = realmAccess.get("roles");
        var grants = realmAccess.get("roles").stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).toList();
        return new JwtAuthenticationToken(jwt, grants);
    }
}
