package ca.nrc.cadc.auth;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;

import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.vosi.avail.CheckResource;
import ca.nrc.cadc.vosi.avail.CheckWebService;

/**
 * Implementation of default Authenticator for AuthenticationUtil in cadcUtil.
 * This class augments the subject with additional identities using the access
 * control library.
 *
 * @author pdowler
 */
public class AuthenticatorImpl implements Authenticator
{

    private static final Logger log = Logger.getLogger(AuthenticatorImpl.class);

    public AuthenticatorImpl()
    {
    }

    /**
     * @param subject
     * @return the possibly modified subject
     */
    public Subject getSubject(Subject subject)
    {
        AuthMethod am = AuthenticationUtil.getAuthMethod(subject);
        if (am == null || AuthMethod.ANON.equals(am))
        {
            return subject;
        }

        if (subject != null && subject.getPrincipals().size() > 0)
        {
            Profiler prof = new Profiler(AuthenticatorImpl.class);
            ACIdentityManager identityManager = new ACIdentityManager();
            identityManager.augmentSubject(subject);
            prof.checkpoint("AuthenticatorImpl.augmentSubject()");

            if (subject.getPrincipals(HttpPrincipal.class).isEmpty()) // no matching cadc account
            {
                // check to see if they connected with an client certificate at least
                // they should be able to use services with only a client certificate
                if (subject.getPrincipals(X500Principal.class).isEmpty())
                {
                    // if the caller had an invalid or forged CADC_SSO cookie, we could get
                    // in here and then not match any known identity: drop to anon
                    log.debug("HttpPrincipal not found - dropping to anon: " + subject);
                    subject = AuthenticationUtil.getAnonSubject();
                }
            }
        }

        return subject;
    }

    public static CheckResource getAvailabilityCheck()
    {
        try
        {
            RegistryClient regClient = new RegistryClient();
            LocalAuthority localAuth = new LocalAuthority();
            URI serviceURI = localAuth.getServiceURI("gms");
            URL availURL = regClient.getServiceURL(serviceURI, "http", "/availability");
            return new CheckWebService(availURL.toExternalForm());
        }
        catch (MalformedURLException e)
        {
            throw new RuntimeException(e);
        }
    }
}
