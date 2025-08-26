package ca.nrc.cadc.accesscontrol.web;


import ca.nrc.cadc.accesscontrol.AccessControlClient;

import java.io.IOException;
import java.net.URI;


/**
 * Wrapper around the legacy LoginUtil.  Exists to provide a good instance that
 * can be reused, and to make it unit testable.
 */
public class LoginAuthenticator
{
    private final AccessControlClient accessControlClient;


    LoginAuthenticator()
    {
        this(new AccessControlClient(URI.create("ivo://cadc.nrc.ca/gms")));
    }

    LoginAuthenticator(final AccessControlClient accessControlClient)
    {
        this.accessControlClient = accessControlClient;
    }


    /**
     * Authenticate the given username and password.
     *
     * @param username          The username to authenticate.
     * @param password          The entered password.
     * @return                  True if good username/password combination, or
     *                          False otherwise.
     * @throws IOException      Any unforeseen error.
     */
    String authenticate(final String username, final String password)
            throws IOException
    {
        return accessControlClient.login(username, password.toCharArray());
    }
}
