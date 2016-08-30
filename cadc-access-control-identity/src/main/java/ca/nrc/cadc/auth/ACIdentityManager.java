package ca.nrc.cadc.auth;

import java.io.File;
import java.net.URI;
import java.net.URL;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.sql.Types;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.client.UserClient;
import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.vosi.avail.CheckResource;
import ca.nrc.cadc.vosi.avail.CheckWebService;

/**
 * AC implementation of the IdentityManager interface. This
 * implementation returns the NumericPrincipal.
 *
 * @author pdowler
 */
public class ACIdentityManager implements IdentityManager
{
    private static final Logger log = Logger.getLogger(ACIdentityManager.class);

    private static final File DEFAULT_PRIVILEGED_PEM_FILE = new File(System.getProperty("user.home") + "/.ssl/cadcproxy.pem");
    private static final String ALT_PEM_KEY = ACIdentityManager.class.getName() + ".pemfile";

    private File privilegedPemFile;

    public ACIdentityManager()
    {
        privilegedPemFile = DEFAULT_PRIVILEGED_PEM_FILE;
        String altPemFile = System.getProperty(ALT_PEM_KEY);
        if (altPemFile != null)
        {
            privilegedPemFile = new File(altPemFile);
        }
    }

    /**
     * Returns a storage type constant from java.sql.Types.
     *
     * @return Types.INTEGER
     */
    public int getOwnerType()
    {
        return Types.INTEGER;
    }

    /**
     * Returns a value of type specified by getOwnerType() for storage.
     *
     * @param subject
     * @return an Integer internal CADC ID
     */
    public Object toOwner(Subject subject)
    {
        X500Principal x500Principal = null;
        if (subject != null)
        {
            Set<Principal> principals = subject.getPrincipals();
            for (Principal principal : principals)
            {
                if (principal instanceof NumericPrincipal)
                {
                    NumericPrincipal cp = (NumericPrincipal) principal;
                    UUID id = cp.getUUID();
                    Long l = Long.valueOf(id.getLeastSignificantBits());
                    return l.intValue();
                }
                if (principal instanceof X500Principal)
                {
                    x500Principal = (X500Principal) principal;
                }
            }
        }

        if (x500Principal == null)
        {
            return null;
        }

        // The user has connected with a valid client cert but does
        // not have an account (no numeric principal).
        // Create an auto-approved account with their x500Principal.
        NumericPrincipal numericPrincipal = createX500User(x500Principal);
        subject.getPrincipals().add(numericPrincipal);
        return Long.valueOf(numericPrincipal.getUUID().getLeastSignificantBits());
    }

    private NumericPrincipal createX500User(final X500Principal x500Principal)
    {
        PrivilegedExceptionAction<NumericPrincipal> action = new PrivilegedExceptionAction<NumericPrincipal>()
        {
            @Override
            public NumericPrincipal run() throws Exception
            {
                LocalAuthority localAuth = new LocalAuthority();
                URI serviceURI = localAuth.getServiceURI(Standards.UMS_USERS_01.toASCIIString());

                UserClient userClient = new UserClient(serviceURI);
                User newUser = userClient.createUser(x500Principal);

                Set<NumericPrincipal> set = newUser.getIdentities(NumericPrincipal.class);
                if (set.isEmpty())
                {
                    throw new IllegalStateException("missing internal id");
                }
                return set.iterator().next();
            }
        };

        Subject servopsSubject = SSLUtil.createSubject(privilegedPemFile);
        try
        {
            return Subject.doAs(servopsSubject, action);
        }
        catch (Exception e)
        {
            throw new IllegalStateException("failed to create internal id for user " + x500Principal.getName(), e);
        }
    }

    /**
     * Get a consistent string representation of the user.
     *
     * @param subject
     * @return an X509 distinguished name
     */
    public String toOwnerString(Subject subject)
    {
        if (subject != null)
        {
            Set<Principal> principals = subject.getPrincipals();
            for (Principal principal : principals)
            {
                if (principal instanceof X500Principal)
                {
                    return principal.getName();
                }
            }
        }
        return null;
    }

    /**
     * Reconstruct the subject from the stored object. This method also
     * re-populates the subject with all know alternate principals.
     *
     * @param o the stored object
     * @return the complete subject
     */
    public Subject toSubject(Object o)
    {
        try
        {
            if (o == null || !(o instanceof Integer))
            {
                return null;
            }
            Integer i = (Integer) o;
            if (i <= 0)
            {
                // identities <= 0 are internal
                return new Subject();
            }

            UUID uuid = new UUID(0L, (long) i);
            NumericPrincipal p = new NumericPrincipal(uuid);
            Set<Principal> pset = new HashSet<Principal>();
            pset.add(p);
            Subject ret = new Subject(false, pset, new HashSet(), new HashSet());

            Profiler prof = new Profiler(ACIdentityManager.class);
            augmentSubject(ret);
            prof.checkpoint("CadcIdentityManager.augmentSubject");

            return ret;
        }
        finally
        {

        }
    }

    public void augmentSubject(final Subject subject)
    {
        try
        {
            PrivilegedExceptionAction<Object> action = new PrivilegedExceptionAction<Object>()
            {
                public Object run() throws Exception
                {
                    LocalAuthority localAuth = new LocalAuthority();
                    URI serviceURI = localAuth.getServiceURI(Standards.UMS_USERS_01.toASCIIString());

                    UserClient userClient = new UserClient(serviceURI);
                    userClient.augmentSubject(subject);
                    return null;
                }
            };

            log.debug("privileged user cert: " + privilegedPemFile.getAbsolutePath());
            Subject servopsSubject = SSLUtil.createSubject(privilegedPemFile);
            Subject.doAs(servopsSubject, action);
        }
        catch (PrivilegedActionException e)
        {
            String msg = "Error augmenting subject " + subject;
            throw new RuntimeException(msg, e);
        }
    }

    /**
     * The returned CheckResource is the same as the one from AuthenticatorImpl.
     *
     * @return the CheckResource
     */
    public static CheckResource getAvailabilityCheck()
    {
        RegistryClient regClient = new RegistryClient();
        LocalAuthority localAuth = new LocalAuthority();
        URI serviceURI = localAuth.getServiceURI(Standards.UMS_USERS_01.toASCIIString());
        URL availURL = regClient.getServiceURL(serviceURI, Standards.VOSI_AVAILABILITY, AuthMethod.ANON);
        return new CheckWebService(availURL.toExternalForm());
    }
}
