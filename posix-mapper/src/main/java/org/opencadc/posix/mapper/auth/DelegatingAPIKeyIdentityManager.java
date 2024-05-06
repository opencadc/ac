package org.opencadc.posix.mapper.auth;

import ca.nrc.cadc.auth.*;

import javax.security.auth.Subject;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;


/**
 * Special IdentityManager to enable delegating most tasks to the configured IdentityManager, but with the special
 * case to validate pre-agreed upon API keys.
 */
public class DelegatingAPIKeyIdentityManager implements IdentityManager {
    public static final File DEFAULT_KEY_FOLDER = new File(System.getProperty("user.home") + "/config/keys");
    public static final String AUTHORIZATION_KEY = "api-key";

    // Ugly way to store the currently delegated identity manager.  This is set by this service's one-time listener.
    public static IdentityManager DELEGATED_IDENTITY_MANAGER;


    @Override
    public Set<URI> getSecurityMethods() {
        return Set.of();
    }

    @Override
    public Subject validate(final Subject subject) throws NotAuthenticatedException {
        // Will be null for API Key tokens.
        final AuthMethod authMethod = AuthenticationUtil.getAuthMethod(subject);

        // Any header with the Authorization key.
        final Set<AuthorizationTokenPrincipal> rawAPIKeyTokens =
                subject.getPrincipals(AuthorizationTokenPrincipal.class)
                       .stream()
                       .filter(token -> {
                           final String value = token.getHeaderValue();
                           return value != null
                                   && value.trim().toLowerCase()
                                           .startsWith(DelegatingAPIKeyIdentityManager.AUTHORIZATION_KEY);
                       })
                       .collect(Collectors.toSet());

        if (!rawAPIKeyTokens.isEmpty() && authMethod == null) {
            final File[] keyFiles = DelegatingAPIKeyIdentityManager.DEFAULT_KEY_FOLDER.listFiles();
            if (keyFiles != null) {
                final Map<String, String> matchingKeyFiles = new HashMap<>();
                for (final File keyFile : keyFiles) {
                    if (keyFile.isFile() && keyFile.canRead()) {
                        try (final BufferedReader reader = new BufferedReader(new FileReader(keyFile))) {
                            // Token value from the file.
                            final String line = reader.readLine();
                            if (rawAPIKeyTokens
                                    .stream()
                                    .map(token -> {
                                        final String value = token.getHeaderValue().trim();
                                        return value.substring(
                                                DelegatingAPIKeyIdentityManager.AUTHORIZATION_KEY.length()).trim();
                                    })
                                    .anyMatch(token -> token.equals(line))) {
                                matchingKeyFiles.put(keyFile.getName(), line);
                                subject.getPrincipals().removeAll(rawAPIKeyTokens);
                            }
                        } catch (IOException ioException) {
                            throw new IllegalStateException(ioException.getMessage(), ioException);
                        }
                    }
                }

                // TODO: Verify client calling is what the key says it is.
                if (matchingKeyFiles.isEmpty()) {
                    throw new NotAuthenticatedException("No API Keys matching.");
                } else {
                    matchingKeyFiles.forEach((key, value) -> {
                        final AuthorizationToken authorizationToken =
                                new AuthorizationToken("bearer", value, Collections.emptyList(), null);
                        subject.getPublicCredentials().add(authorizationToken);
                    });

                    return subject;
                }
            } else {
                throw new IllegalStateException("No Key files available in "
                                                        + DelegatingAPIKeyIdentityManager.DEFAULT_KEY_FOLDER);
            }
        } else {
            return DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER.validate(subject);
        }
    }

    @Override
    public Subject augment(Subject subject) {
        return DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER.augment(subject);
    }

    @Override
    public Subject toSubject(Object o) {
        return DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER.toSubject(o);
    }

    @Override
    public Object toOwner(Subject subject) {
        return DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER.toOwner(subject);
    }

    @Override
    public String toDisplayString(Subject subject) {
        return DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER.toDisplayString(subject);
    }
}
