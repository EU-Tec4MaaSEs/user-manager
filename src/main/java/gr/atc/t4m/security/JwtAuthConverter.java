package gr.atc.t4m.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;

@Component
@Slf4j
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter=new JwtGrantedAuthoritiesConverter();

    private static final String CLAIM_REALM_ACCESS = "realm_access";
    private static final String CLAIM_RESOURCE_ACCESS = "resource_access";
    private static final String CLAIM_ROLES = "roles";

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) throws NullPointerException {
        Collection<GrantedAuthority> authorities = Stream.concat(
          Optional.of(jwtGrantedAuthoritiesConverter.convert(jwt)).orElseGet(Collections::emptyList).stream(),
                extractKeycloakRoles(jwt).stream()
        ).collect(Collectors.toSet());

        return new JwtAuthenticationToken(jwt, authorities,jwt.getClaim("preferred_username"));
    }

    private Collection<GrantedAuthority> extractKeycloakRoles(Jwt jwt) {
        try {
            Set<String> roles = new HashSet<>();

            // Extract realm roles
            Map<String, Object> realmAccess = jwt.getClaim(CLAIM_REALM_ACCESS);
            if (realmAccess != null) {
                roles.addAll(extractRolesFromClaim(realmAccess));
            }

            // Extract resource roles
            Map<String, Object> resourceAccess = jwt.getClaim(CLAIM_RESOURCE_ACCESS);

            if (resourceAccess != null) {
                resourceAccess.values().stream()
                        .filter(Map.class::isInstance) // Ensure instance of Map
                        .map(obj -> {
                            Map<?, ?> map = (Map<?, ?>) obj;
                            return castToMapStringObject(map);
                        })
                        .map(this::extractRolesFromClaim)
                        .forEach(roles::addAll);
            }

            return roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .collect(toList());

        }catch (Exception e){
            return Collections.emptyList();
        }
    }

    /**
     * Safely cast a raw Map to Map<String, Object> while checking key types.
     */
    private Map<String, Object> castToMapStringObject(Map<?, ?> rawMap) {
        Map<String, Object> safeMap = new HashMap<>();
        for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
            if (entry.getKey() instanceof String) {
                safeMap.put((String) entry.getKey(), entry.getValue());
            }
        }
        return safeMap;
    }

    private List<String> extractRolesFromClaim(Map<String, Object> claimMap) {
        Object rolesObj = claimMap.get(CLAIM_ROLES);
        if (rolesObj instanceof List<?>) {
            return ((List<?>) rolesObj).stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
        }
        return Collections.emptyList();
    }
}