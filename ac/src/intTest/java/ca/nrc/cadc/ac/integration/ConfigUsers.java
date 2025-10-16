/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2025.                            (c) 2025.
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 *  All rights reserved                  Tous droits réservés
 *
 *  NRC disclaims any warranties,        Le CNRC dénie toute garantie
 *  expressed, implied, or               énoncée, implicite ou légale,
 *  statutory, of any kind with          de quelque nature que ce
 *  respect to the software,             soit, concernant le logiciel,
 *  including without limitation         y compris sans restriction
 *  any warranty of merchantability      toute garantie de valeur
 *  or fitness for a particular          marchande ou de pertinence
 *  purpose. NRC shall not be            pour un usage particulier.
 *  liable in any event for any          Le CNRC ne pourra en aucun cas
 *  damages, whether direct or           être tenu responsable de tout
 *  indirect, special or general,        dommage, direct ou indirect,
 *  consequential or incidental,         particulier ou général,
 *  arising from the use of the          accessoire ou fortuit, résultant
 *  software.  Neither the name          de l'utilisation du logiciel. Ni
 *  of the National Research             le nom du Conseil National de
 *  Council of Canada nor the            Recherches du Canada ni les noms
 *  names of its contributors may        de ses  participants ne peuvent
 *  be used to endorse or promote        être utilisés pour approuver ou
 *  products derived from this           promouvoir les produits dérivés
 *  software without specific prior      de ce logiciel sans autorisation
 *  written permission.                  préalable et particulière
 *                                       par écrit.
 *
 *  This file is part of the             Ce fichier fait partie du projet
 *  OpenCADC project.                    OpenCADC.
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la “GNU Affero General Public
 *  License as published by the          License” telle que publiée
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)         licence, soit (à votre gré)
 *  any later version.                   toute version ultérieure.
 *
 *  OpenCADC is distributed in the       OpenCADC est distribué
 *  hope that it will be useful,         dans l’espoir qu’il vous
 *  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 *  without even the implied             GARANTIE : sans même la garantie
 *  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
 *  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
 *  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 *  General Public License for           Générale Publique GNU Affero
 *  more details.                        pour plus de détails.
 *
 *  You should have received             Vous devriez avoir reçu une
 *  a copy of the GNU Affero             copie de la Licence Générale
 *  General Public License along         Publique GNU Affero avec
 *  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
 *  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 *                                       <http://www.gnu.org/licenses/>.
 *
 *  $Revision: 4 $
 *
 ************************************************************************
 */

package ca.nrc.cadc.ac.integration;

import ca.nrc.cadc.ac.client.UserClient;
import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.auth.BasicX509TrustManager;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.net.NetrcFile;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.RegistryClient;
import ca.nrc.cadc.util.FileUtil;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.net.URL;
import java.security.PrivilegedExceptionAction;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;
import org.junit.Assert;
import static org.junit.Assert.assertEquals;

/**
 * Common class to produce authentication credentials for different types of users of the ac system configured through
 * their X509 certificates.
 *
 * AC Integration tests require the following users (name of corresponding cert files)
 * - ac-group-owner.pem : owner of test group
 * - ac-group-member.pem : member of test group
 * - ac-registered-user.pem : registered user but not a member in any group, e.g. authenticated but not authorized
 * - ac-anon-user.pem : unregistered user
 * - ac-priv-user.pem : privileged user capable of augmenting subject
 * - ~/.netrc entry for the host part of the ac service URL with login and password for a registered user. It can be
 * one of the above users.
 *
 * @author andamian
 */
public class ConfigUsers {
    private static final Logger log = Logger.getLogger(ConfigUsers.class);

    private String ownerUsername;
    private String memberUsername;
    private String registeredUsername;

    private Subject augmentedOwnerSubject;

    private static final String ONWER_CERT_FILE = "ac-group-owner.pem";
    private static final String MEMBER_CERT_FILE = "ac-group-member.pem";
    private static final String REGISTERED_CERT_FILE = "ac-registered-user.pem";
    private static final String ANON_CERT_FILE = "ac-anon-user.pem";
    private static final String PRIV_CERT_FILE = "ac-priv-user.pem";

    public static final String AC_SERVICE_ID = "ivo://opencadc.org/gms"; // TODO make configurable

    PasswordAuthentication passwordAuthUser;
    private static ConfigUsers instance;

    private ConfigUsers() {
        log.debug("User serviceURI: " + AC_SERVICE_ID);
    }

    public static ConfigUsers getInstance() {
        if (instance == null) {
            instance = new ConfigUsers();
        }
        return instance;
    }

    public String getOwnerUsername() {
        if (ownerUsername == null) {
            ownerUsername = getUsername(ONWER_CERT_FILE);
        }
        return ownerUsername;
    }

    public Subject getOwnerSubject() {
        return SSLUtil.createSubject(FileUtil.getFileFromResource(ONWER_CERT_FILE, ConfigUsers.class));
    }

    public Subject getAugmentedOwnerSubject() {
        if (augmentedOwnerSubject == null) {
            augmentedOwnerSubject = getAugmentedSubject(ONWER_CERT_FILE);
        }
        return augmentedOwnerSubject;
    }

    public String getMemberUsername() {
        if (memberUsername == null) {
            memberUsername = getUsername(MEMBER_CERT_FILE);
        }
        return memberUsername;
    }

    public Subject getMemberSubject() {
        return SSLUtil.createSubject(FileUtil.getFileFromResource(MEMBER_CERT_FILE, ConfigUsers.class));
    }

    public String getRegisteredUsername() {
        if (registeredUsername == null) {
            registeredUsername = getUsername(REGISTERED_CERT_FILE);
        }
        return registeredUsername;
    }

    public Subject getRegisteredSubject() {
        return SSLUtil.createSubject(FileUtil.getFileFromResource(REGISTERED_CERT_FILE, ConfigUsers.class));
    }

    public Subject getAnonSubject() {
        return SSLUtil.createSubject(FileUtil.getFileFromResource(ANON_CERT_FILE, ConfigUsers.class));
    }

    public Subject getPrivSubject() {
        return SSLUtil.createSubject(FileUtil.getFileFromResource(PRIV_CERT_FILE, ConfigUsers.class));
    }


    public Subject getAugmentedSubject(String certFile) {
        Subject subject = SSLUtil.createSubject(FileUtil.getFileFromResource(certFile, ConfigUsers.class));
        try {
            Subject.doAs(subject, new PrivilegedExceptionAction<Object>() {
                @Override
                public Object run() throws Exception {
                    UserClient client = new UserClient(new URI(AC_SERVICE_ID));
                    client.augmentSubject(subject);
                    return null;
                }

            });
            return subject;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            log.error("unexpected", e);
            Assert.fail("Caught an unexpected exception: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private String getUsername(String certFile) {
        Subject subject = getAugmentedSubject(certFile);
        final Set<HttpPrincipal> httpPrincipals = subject.getPrincipals(HttpPrincipal.class);
        assertEquals("Expected exactly one HttpPrincipal in subject for cert: " + certFile, 1, httpPrincipals.size());
        return httpPrincipals.iterator().next().getName();
    }

    /**
     * Get the credentials for a registered user from the .netrc file.
     * The .netrc file must contain an entry for the host part of the ac service URL.
     * @return PasswordAuthentication containing the login and password
     */
    public PasswordAuthentication getPasswordAuthUser() {
        if (passwordAuthUser == null) {
            NetrcFile netrc = new NetrcFile();
            RegistryClient regClient = new RegistryClient();
            URL loginUrl = regClient
                    .getServiceURL(URI.create(ConfigUsers.AC_SERVICE_ID), Standards.UMS_LOGIN_01, AuthMethod.ANON);
            log.info("loginUrl: " + loginUrl);
            passwordAuthUser = netrc.getCredentials(loginUrl.getHost(), true);
            Assert.assertNotNull("~/.netrc credentials required for host: " + loginUrl.getHost(), passwordAuthUser);
        }
        return passwordAuthUser;
    }
}
