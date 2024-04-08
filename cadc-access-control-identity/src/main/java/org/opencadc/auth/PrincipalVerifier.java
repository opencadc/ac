package org.opencadc.auth;

import ca.nrc.cadc.auth.NotAuthenticatedException;

import javax.security.auth.x500.X500Principal;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Simple verifier for white-listing Distinguished Names (Principals).
 */
public class PrincipalVerifier {
    private final Set<Principal> allowedPrincipals = new HashSet<>();

    public PrincipalVerifier(Principal... allowedPrincipals) {
        if (allowedPrincipals == null || allowedPrincipals.length == 0) {
            throw new IllegalStateException("Must supply at least one allowed X500 DN.");
        }

        this.allowedPrincipals.addAll(Arrays.asList(allowedPrincipals));
    }

    /**
     * Verify the provided X509 Certificate with the known list of DNs.
     * @param x500Principal   The X500 Principal to verify.
     * @throws NotAuthenticatedException    If the provided X500 principal is not allowed.
     */
    public void verify(final X500Principal x500Principal) {
        if (!allowedPrincipals.contains(x500Principal)) {
            throw new NotAuthenticatedException("User '" + x500Principal + "' not authorized.");
        }
    }
}
