/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2014.                            (c) 2014.
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
package ca.nrc.cadc.ac.server.ldap;

import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.profiler.Profiler;
import java.security.AccessControlException;
import java.security.GeneralSecurityException;
import java.util.Random;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import org.apache.log4j.Logger;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;


public abstract class LdapDAO {
    private static final Logger logger = Logger.getLogger(LdapDAO.class);

    // LDAP attributes common to LdapUser and LdapGroup
    protected static final String LDAP_OBJECT_CLASS = "objectClass";
    protected static final String LDAP_GID_NUMBER = "gidNumber";
    protected static final String LDAP_CN = "cn";
    protected static final String LDAP_ENTRYDN = "entrydn";
    protected static final String LDAP_INET_USER = "inetuser";
    protected static final String LDAP_NSACCOUNTLOCK = "nsaccountlock";

    private final LdapConnections connections;
    protected LdapConfig config;


    public LdapDAO(LdapConnections connections) {
        this.connections = connections;
        config = connections.getCurrentConfig();
        logger.debug("New LdapDAO instance, config: " + config);
    }

    public LDAPConnection getReadOnlyConnection() throws TransientException {
        return connections.getReadOnlyConnection();
    }

    public LDAPConnection getReadWriteConnection() throws TransientException {
        return connections.getReadWriteConnection();
    }

    public LDAPConnection getUnboundReadConnection() throws TransientException {
        return connections.getUnboundReadOnlyConnection();
    }

    public void close() {
        connections.releaseConnections();
    }

    /**
     * Method to return a randomly generated user numeric ID. The default
     * implementation returns a value between 20000 and Integer.MAX_VALUE.
     * Services that support a different mechanism for generating numeric
     * IDs override this method.
     *
     * @return Next random numeric ID to use.
     */
    protected int genNextNumericId() {
        Random rand = new Random();
        return rand.nextInt(Integer.MAX_VALUE - 20000) + 20000;
    }

    /**
     * Checks the Ldap result code, and if the result is not SUCCESS,
     * throws an appropriate exception. This is the place to decide on
     * mapping between ldap errors and exception types
     *
     * @param code The code returned from an LDAP request.
     * @throws TransientException If unexpected, temporary error occurs
     */
    protected static void checkLdapResult(ResultCode code)
            throws TransientException {
        logger.debug("Ldap result: " + code);
        checkLdapResult(code, false, null);
    }

    protected static void checkLdapResult(LDAPException e) throws TransientException {
        checkLdapResult(e.getResultCode(), false, e.getMessage());
    }

    protected static void checkLdapResult(ResultCode code, boolean ignoreNoSuchAttribute, String errorMessage)
            throws TransientException {
        if (code == ResultCode.SUCCESS
                || code == ResultCode.NO_SUCH_OBJECT
                || (ignoreNoSuchAttribute && code == ResultCode.NO_SUCH_ATTRIBUTE)) {
            return;
        }

        if (code == ResultCode.INSUFFICIENT_ACCESS_RIGHTS) {
            throw new AccessControlException("Not authorized ");
        } else if (code == ResultCode.INVALID_CREDENTIALS) {
            throw new AccessControlException("Invalid credentials ");
        } else if (code == ResultCode.PARAM_ERROR) {
            throw new IllegalArgumentException("Error in Ldap parameters ");
        } else if (code == ResultCode.BUSY || code == ResultCode.CONNECT_ERROR) {
            throw new TransientException("Connection problems ");
        } else if (code == ResultCode.TIMEOUT || code == ResultCode.TIME_LIMIT_EXCEEDED) {
            throw new TransientException("ldap timeout");
        } else if (code == ResultCode.INVALID_DN_SYNTAX) {
            throw new IllegalArgumentException("Invalid DN syntax");
        } else if (code == ResultCode.CONSTRAINT_VIOLATION) {
            if (errorMessage != null) {
                throw new IllegalArgumentException(errorMessage);
            } else {
                throw new IllegalArgumentException("Invalid Password Syntax");
            }
        }

        throw new RuntimeException("Ldap error (" + code.getName() + ")");
    }


    static SocketFactory getSocketFactory(LdapConfig.LdapPool poolConfig) {
        final SocketFactory socketFactory;

        if (poolConfig.isSecure()) {
            Profiler profiler = new Profiler(LdapDAO.class);
            socketFactory = createSSLSocketFactory();
            profiler.checkpoint("createSSLSocketFactory");
        } else {
            socketFactory = SocketFactory.getDefault();
        }

        return socketFactory;
    }

    static SSLSocketFactory createSSLSocketFactory() {
        try {
            return new com.unboundid.util.ssl.SSLUtil().
                    createSSLSocketFactory();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Unexpected error.", e);
        }
    }
}
