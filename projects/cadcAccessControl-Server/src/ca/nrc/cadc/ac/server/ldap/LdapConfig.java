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

import ca.nrc.cadc.util.StringUtil;
import java.io.IOException;
import java.net.URL;
import java.util.Properties;
import org.apache.log4j.Logger;

public class LdapConfig
{
    private static final Logger logger = Logger.getLogger(LdapConfig.class);

    public static final String CONFIG = LdapConfig.class.getSimpleName() + 
                                        ".properties";
    public static final String LDAP_SERVER = "server";
    public static final String LDAP_PORT = "port";
    public static final String LDAP_ADMIN = "admin";
    public static final String LDAP_PASSWD = "passwd";
    public static final String LDAP_USERS_DN = "usersDn";
    public static final String LDAP_GROUPS_DN = "groupsDn";
    public static final String LDAP_DELETED_GROUPS_DN = "deletedGroupsDn";

    private String usersDN;
    private String groupsDN;
    private String deletedGroupsDN;
    private String server;
    private int port;
    private String adminUserDN;
    private String adminPasswd;

    public static LdapConfig getLdapConfig()
    {
        Properties config = new Properties();
        URL url = null;
        try
        {
            url = LdapConfig.class.getClassLoader().getResource(CONFIG);
            logger.debug("Using config from: " + url);
            if (url != null)
            {
                config.load(url.openStream());
            }
            else
            {
                throw new IOException("File not found");
            }
        }
        catch (Exception ex)
        {
            throw new RuntimeException("failed to read " + CONFIG + 
                                       " from " + url, ex);
        }

        String server = config.getProperty(LDAP_SERVER);
        if (!StringUtil.hasText(server))
        {
            throw new RuntimeException("failed to read property " + 
                                       LDAP_SERVER);
        }

        String port = config.getProperty(LDAP_PORT);
        if (!StringUtil.hasText(port))
        {
            throw new RuntimeException("failed to read property " + LDAP_PORT);
        }

        String ldapAdmin = config.getProperty(LDAP_ADMIN);
        if (!StringUtil.hasText(ldapAdmin))
        {
            throw new RuntimeException("failed to read property " + LDAP_ADMIN);
        }

        String ldapPasswd = config.getProperty(LDAP_PASSWD);
        if (!StringUtil.hasText(ldapPasswd))
        {
            throw new RuntimeException("failed to read property " + 
                                       LDAP_PASSWD);
        }

        String ldapUsersDn = config.getProperty(LDAP_USERS_DN);
        if (!StringUtil.hasText(ldapUsersDn))
        {
            throw new RuntimeException("failed to read property " + 
                                       LDAP_USERS_DN);
        }

        String ldapGroupsDn = config.getProperty(LDAP_GROUPS_DN);
        if (!StringUtil.hasText(ldapGroupsDn))
        {
            throw new RuntimeException("failed to read property " + 
                                       LDAP_GROUPS_DN);
        }

        String ldapDeletedGroupsDn = config.getProperty(LDAP_DELETED_GROUPS_DN);
        if (!StringUtil.hasText(ldapDeletedGroupsDn))
        {
            throw new RuntimeException("failed to read property " + 
                                       LDAP_DELETED_GROUPS_DN);
        }

        return new LdapConfig(server, Integer.valueOf(port), ldapAdmin, 
                              ldapPasswd, ldapUsersDn, ldapGroupsDn, 
                              ldapDeletedGroupsDn);
    }

    public LdapConfig(String server, int port, String adminUserDN, 
                      String adminPasswd, String usersDN, String groupsDN, 
                      String deletedGroupsDN)
    {
        if (!StringUtil.hasText(server))
        {
            throw new IllegalArgumentException("Illegal LDAP server name: " + 
                                               server);
        }
        if (port < 0)
        {
            throw new IllegalArgumentException("Illegal LDAP server port: " + 
                                               port);
        }
        if (!StringUtil.hasText(adminUserDN))
        {
            throw new IllegalArgumentException("Illegal Admin DN: " + 
                                               adminUserDN);
        }
        if (!StringUtil.hasText(adminPasswd))
        {
            throw new IllegalArgumentException("Illegal Admin password: " + 
                                               adminPasswd);
        }
        if (!StringUtil.hasText(usersDN))
        {
            throw new IllegalArgumentException("Illegal users LDAP DN: " + 
                                               usersDN);
        }
        if (!StringUtil.hasText(groupsDN))
        {
            throw new IllegalArgumentException("Illegal groups LDAP DN: " + 
                                               groupsDN);
        }
        if (!StringUtil.hasText(deletedGroupsDN))
        {
            throw new IllegalArgumentException("Illegal groups LDAP DN: " + 
                                               deletedGroupsDN);
        }

        this.server = server;
        this.port = port;
        this.adminUserDN = adminUserDN;
        this.adminPasswd = adminPasswd;
        this.usersDN = usersDN;
        this.groupsDN = groupsDN;
        this.deletedGroupsDN = deletedGroupsDN;
    }

    public String getUsersDN()
    {
        return this.usersDN;
    }

    public String getGroupsDN()
    {
        return this.groupsDN;
    }

    public String getDeletedGroupsDN()
    {
        return this.deletedGroupsDN;
    }

    public String getServer()
    {
        return this.server;
    }

    public int getPort()
    {
        return this.port;
    }

    public String getAdminUserDN()
    {
        return this.adminUserDN;
    }

    public String getAdminPasswd()
    {
        return this.adminPasswd;
    }

}
