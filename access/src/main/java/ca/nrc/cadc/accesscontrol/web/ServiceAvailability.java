/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2015.                            (c) 2015.
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

package ca.nrc.cadc.accesscontrol.web;

import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.vosi.Availability;
import ca.nrc.cadc.vosi.AvailabilityPlugin;
import ca.nrc.cadc.vosi.avail.CheckResource;
import ca.nrc.cadc.vosi.avail.CheckWebService;
import org.apache.log4j.Logger;

import java.io.File;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Properties;


public class ServiceAvailability implements AvailabilityPlugin {
    private static final Logger log = Logger.getLogger(ServiceAvailability.class);
    
    //private static final String configFileLocation =
    //        System.getProperty("user.home") + "/config/" + SSOLoginServlet.AC_PROPERTIES_FILE;
    //private static final String CANFAR_SSO_SERVER_KEY = "CANFAR_SSO_SERVER";
    //private static final String SSO_RESOURCE = "/access/login";
    //private static final Map<String, Object> parameters;

    //static {
    //    parameters = new HashMap<>();
    //    parameters.put("USERNAME", "foo");
    //    parameters.put("PASSWORD", "bar");
    //}


    private String applicationName;


    /**
     * Set application name. The appName is a string unique to this
     * application.
     *
     * @param appName unique application name
     */
    @Override
    public void setAppName(String appName) {
        applicationName = appName;
    }


    /**
     * A very lightweight method that can be called every few seconds to test if a service is (probably) working.
     * This method is to be implemented by all services.
     *
     * @return true if successful, false otherwise
     */

    @Override
    public boolean heartbeat() {
        return true;
    }

    public Availability getStatus() {
        try {
            checkAccess();
            String message = "/access is available";
            return new Availability(true, message);
        } catch (Throwable t) {
            log.debug("availability exception", t);
            Throwable cause = t;
            if (t.getCause() != null) {
                cause = t.getCause();
            }

            final String message = String.format("%s is not available: %s: %s", applicationName,
                                                 cause.getClass().getSimpleName(), cause.getMessage());
            return new Availability(false, message);
        }
    }

    /**
     * The AvailabilitySerlet supports a POST with state=??? that it will pass
     * on to the WebService. This can be used to implement state-changes in the
     * service, e.g. disabling or enabling features.
     *
     * @param state requested state
     */
    @Override
    public void setState(String state) {
        // Not supported
    }

    private void checkAccess() throws Exception {
        // check other services we depend on
        final RegistryClient reg = new RegistryClient();
        final LocalAuthority localAuthority = new LocalAuthority();
        
        // primary: login
        URI stdID = Standards.SECURITY_METHOD_PASSWORD;
        URI loginURI = localAuthority.getResourceID(stdID);
        log.warn("check: " + stdID + " provider " + loginURI);
        URL url = reg.getServiceURL(loginURI, Standards.VOSI_AVAILABILITY, AuthMethod.ANON);
        CheckResource checkResource = new CheckWebService(url);
        checkResource.check();
        
        // practically, all these checks wil lbe skipped but we need to verify they are configured
        // ... not being too careful andf just letting this fail in some ugly way
        stdID = Standards.UMS_USERS_01;
        URI usersURI = localAuthority.getResourceID(stdID);
        log.warn("check: " + stdID + " provider " + usersURI);
        if (loginURI.equals(usersURI)) {
            log.debug("already checked: " + stdID + " = " + loginURI);
        } else {
            url = reg.getServiceURL(usersURI, Standards.VOSI_AVAILABILITY, AuthMethod.ANON);
            checkResource = new CheckWebService(url);
            checkResource.check();
        }
        
        stdID = Standards.UMS_RESETPASS_01;
        URI resetURI = localAuthority.getResourceID(stdID);
        log.warn("check: " + stdID + " provider " + resetURI);
        if (loginURI.equals(resetURI)) {
            log.debug("already checked: " + stdID + " = " + loginURI);
        } else {
            url = reg.getServiceURL(resetURI, Standards.VOSI_AVAILABILITY, AuthMethod.ANON);
            checkResource = new CheckWebService(url);
            checkResource.check();
        }
        
        stdID = Standards.UMS_REQS_01;
        URI reqURI = localAuthority.getResourceID(stdID);
        log.warn("check: " + stdID + " provider " + reqURI);
        if (loginURI.equals(reqURI)) {
            log.debug("already checked: " + stdID + " = " + loginURI);
        } else {
            url = reg.getServiceURL(reqURI, Standards.VOSI_AVAILABILITY, AuthMethod.ANON);
            checkResource = new CheckWebService(url);
            checkResource.check();
        }
    }
}
