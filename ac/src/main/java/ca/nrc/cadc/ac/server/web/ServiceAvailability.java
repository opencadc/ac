/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2025.                            (c) 2025.
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits reserves
 *
 * NRC disclaims any warranties         Le CNRC denie toute garantie
 * expressed, implied, or statu-        enoncee, implicite ou legale,
 * tory, of any kind with respect       de quelque nature que se soit,
 * to the software, including           concernant le logiciel, y com-
 * without limitation any war-          pris sans restriction toute
 * ranty of merchantability or          garantie de valeur marchande
 * fitness for a particular pur-        ou de pertinence pour un usage
 * pose.  NRC shall not be liable       particulier.  Le CNRC ne
 * in any event for any damages,        pourra en aucun cas etre tenu
 * whether direct or indirect,          responsable de tout dommage,
 * special or general, consequen-       direct ou indirect, particul-
 * tial or incidental, arising          ier ou general, accessoire ou
 * from the use of the software.        fortuit, resultant de l'utili-
 *                                      sation du logiciel.
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */
package ca.nrc.cadc.ac.server.web;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.ac.server.GroupPersistence;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.impl.UserPersistenceImpl;
import ca.nrc.cadc.ac.server.ldap.LdapConfig;
import ca.nrc.cadc.ac.server.ldap.LdapConfig.SystemState;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.PrincipalExtractor;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.vosi.Availability;
import ca.nrc.cadc.vosi.AvailabilityPlugin;
import ca.nrc.cadc.vosi.avail.CheckException;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;

public class ServiceAvailability implements AvailabilityPlugin {

    private static final String CALLER_UID = "cadcregtest1"; // TODO configuration?

    private static final Logger log = Logger.getLogger(ServiceAvailability.class);

    @Override
    public void setAppName(String appName) {
        // no op
    }

    @Override
    public boolean heartbeat() {
        return true;
    }

    public Availability getStatus() {
        String note = "service is accepting requests";
        try {
            LdapConfig ldapConfig = LdapConfig.getLdapConfig();
            if (ldapConfig.getSystemState().equals(SystemState.OFFLINE)) {
                note = "service of offline";
                return new Availability(false, note);
            }

            checkLdap();
            
            if (ldapConfig.getSystemState().equals(SystemState.READONLY)) {
                note = "service is in read-only mode";
                return new Availability(false, note);
            }
            
            note += "; " + getPoolStats();
            return new Availability(true, note);
            
        } catch (CheckException ce) {
            // tests determined that the resource is not working
            note = ce.getMessage();
            return new Availability(false, note);
        } catch (Throwable t) {
            log.error("test failed", t);
            note = "test failed, reason: " + t;
            return new Availability(false, note);
        }
    }

    @Override
    public void setState(String string) {
        // No state changes supported
    }

    private String getPoolStats() throws TransientException {
        PluginFactory factory = new PluginFactory();
        UserPersistenceImpl upi = (UserPersistenceImpl) factory.createUserPersistence();
        return upi.getPoolStatistics();
    }
    
    private void checkLdap() throws Exception {
        try {
            // augment a subject
            Subject subject = AuthenticationUtil.getSubject(new PrincipalExtractor() {
                public Set<Principal> getPrincipals() {
                    Set<Principal> ret = new HashSet<Principal>();
                    ret.add(new HttpPrincipal(CALLER_UID));
                    return ret;
                }

                public X509CertificateChain getCertificateChain() {
                    return null;
                }
            });
            log.debug("test subject: " + subject);
            
            // make one group query
            Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                public Object run() throws Exception {
                    PluginFactory factory = new PluginFactory();
                    GroupPersistence dao = factory.createGroupPersistence();

                    try {
                        Group g = dao.getGroup(UUID.randomUUID().toString());
                    } catch (GroupNotFoundException ignore) {
                    }
                    return null;
                }
            });
        
        } catch (Exception ex) {
            StringBuilder sb = new StringBuilder();
            // strip IllegalStateException
            if (ex.getCause() == null) {
                sb.append("LDAP test query failed - EXCEPTION: " + ex);
                throw new CheckException(sb.toString());
            }
            Throwable t = ex.getCause();
            sb.append("LDAP test query failed - CAUSE: " + t);
            while (t.getCause() != null) {
                t = t.getCause();
                sb.append("\nCAUSE: " + t);
            }
            throw new CheckException(sb.toString());
        }
        
        

    }
}
