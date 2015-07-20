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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;

import org.apache.log4j.Logger;

import ca.nrc.cadc.db.ConnectionConfig;
import ca.nrc.cadc.db.DBConfig;
import ca.nrc.cadc.util.MultiValuedProperties;
import ca.nrc.cadc.util.PropertiesReader;
import ca.nrc.cadc.util.StringUtil;

/**
 * Reads and stores the LDAP configuration information. The information 
 * 
 * @author adriand
 *
 */
public class LdapConfig
{
    private static final Logger logger = Logger.getLogger(LdapConfig.class);

    public static final String CONFIG = LdapConfig.class.getSimpleName() + 
                                        ".properties";
    public static final String LDAP_SERVER = "server";
    public static final String LDAP_PORT = "port";
    public static final String LDAP_SERVER_PROXY_USER = "proxyUser";
    public static final String LDAP_USERS_DN = "usersDn";
    public static final String LDAP_USER_REQUESTS_DN = "userRequestsDN";
    public static final String LDAP_GROUPS_DN = "groupsDn";
    public static final String LDAP_ADMIN_GROUPS_DN  = "adminGroupsDn";

    private final static int SECURE_PORT = 636;

    private String usersDN;
    private String userRequestsDN;
    private String groupsDN;
    private String adminGroupsDN;
    private String server;
    private int port;
    private String proxyUserDN;
    private String proxyPasswd;
    
    public String getProxyUserDN()
    {
        return proxyUserDN;
    }

    public String getProxyPasswd()
    {
        return proxyPasswd;
    }

    public static LdapConfig getLdapConfig()
    {
        return getLdapConfig(CONFIG);
    }

    public static LdapConfig getLdapConfig(final String ldapProperties)
    {
        logger.info("Reading LDAP properties from: " + ldapProperties);
        PropertiesReader pr = new PropertiesReader(ldapProperties);
        
        MultiValuedProperties config = pr.getAllProperties();
        
        if (config == null || config.keySet() == null)
        {
            throw new RuntimeException("failed to read any LDAP property ");
        }
        
        List<String> prop = config.getProperty(LDAP_SERVER);
        if ((prop == null) || (prop.size() != 1))
        {
            throw new RuntimeException("failed to read property " + 
                                       LDAP_SERVER);
        }
        String server = prop.get(0);

        prop = config.getProperty(LDAP_PORT);
        if ((prop == null) || (prop.size() != 1))
        {
            throw new RuntimeException("failed to read property " + LDAP_PORT);
        }
        int port = Integer.valueOf(prop.get(0));
        
        prop = config.getProperty(LDAP_SERVER_PROXY_USER);
        if ((prop == null) || (prop.size() != 1))
        {
            throw new RuntimeException("failed to read property " + 
                    LDAP_SERVER_PROXY_USER);
        }
        String ldapProxy = prop.get(0);
        
        prop = config.getProperty(LDAP_USERS_DN);
        if ((prop == null) || (prop.size() != 1))
        {
            throw new RuntimeException("failed to read property " + 
                                       LDAP_USERS_DN);
        }
        String ldapUsersDn = prop.get(0);
        
        prop = config.getProperty(LDAP_USER_REQUESTS_DN);
        if ((prop == null) || (prop.size() != 1))
        {
            throw new RuntimeException("failed to read property " +
                LDAP_USER_REQUESTS_DN);
        }
        String ldapUserRequestsDn = prop.get(0);

        prop = config.getProperty(LDAP_GROUPS_DN);
        if ((prop == null) || (prop.size() != 1))
        {
            throw new RuntimeException("failed to read property " + 
                                       LDAP_GROUPS_DN);
        }
        String ldapGroupsDn = prop.get(0);
        
        prop = config.getProperty(LDAP_ADMIN_GROUPS_DN);
        if ((prop == null) || (prop.size() != 1))
        {
            throw new RuntimeException("failed to read property " + 
                                       LDAP_ADMIN_GROUPS_DN);
        }
        String ldapAdminGroupsDn = prop.get(0);
        
        DBConfig dbConfig;
        try
        {
            dbConfig = new DBConfig();
        } 
        catch (FileNotFoundException e)
        {
            throw new RuntimeException("failed to find .dbrc file ");
        } 
        catch (IOException e)
        {
            throw new RuntimeException("failed to read .dbrc file ");
        }
        ConnectionConfig cc = dbConfig.getConnectionConfig(server, ldapProxy);
        if ( (cc == null) || (cc.getUsername() == null) || (cc.getPassword() == null))
        {
            throw new RuntimeException("failed to find connection info in ~/.dbrc");
        }
        
        return new LdapConfig(server, Integer.valueOf(port), cc.getUsername(), 
                              cc.getPassword(), ldapUsersDn, ldapUserRequestsDn,
                              ldapGroupsDn, ldapAdminGroupsDn);
    }
    

    public LdapConfig(String server, int port, String proxyUserDN, 
                      String proxyPasswd, String usersDN, String userRequestsDN,
                      String groupsDN, String adminGroupsDN)
    {
        if (!StringUtil.hasText(server))
        {
            throw new IllegalArgumentException("Illegal LDAP server name");
        }
        if (port < 0)
        {
            throw new IllegalArgumentException("Illegal LDAP server port: " + 
                                               port);
        }
        if (!StringUtil.hasText(proxyUserDN))
        {
            throw new IllegalArgumentException("Illegal Admin DN");
        }
        if (!StringUtil.hasText(proxyPasswd))
        {
            throw new IllegalArgumentException("Illegal Admin password");
        }
        if (!StringUtil.hasText(usersDN))
        {
            throw new IllegalArgumentException("Illegal users LDAP DN");
        }
        if (!StringUtil.hasText(userRequestsDN))
        {
            throw new IllegalArgumentException("Illegal userRequests LDAP DN");
        }
        if (!StringUtil.hasText(groupsDN))
        {
            throw new IllegalArgumentException("Illegal groups LDAP DN");
        }
        if (!StringUtil.hasText(adminGroupsDN))
        {
            throw new IllegalArgumentException("Illegal admin groups LDAP DN");
        }
        
        this.server = server;
        this.port = port;
        this.proxyUserDN = proxyUserDN;
        this.proxyPasswd = proxyPasswd;
        this.usersDN = usersDN;
        this.userRequestsDN = userRequestsDN;
        this.groupsDN = groupsDN;
        this.adminGroupsDN = adminGroupsDN;
        logger.debug(toString());
    }

    public String getUsersDN()
    {
        return this.usersDN;
    }
    
    public String getUserRequestsDN()
    {
        return this.userRequestsDN;
    }

    public String getGroupsDN()
    {
        return this.groupsDN;
    }
    
    public String getAdminGroupsDN()
    {
        return this.adminGroupsDN;
    }

    public String getServer()
    {
        return this.server;
    }

    public int getPort()
    {
        return this.port;
    }

    public boolean isSecure()
    {
        return getPort() == SECURE_PORT;
    }

    public String getAdminUserDN()
    {
        return this.proxyUserDN;
    }

    public String getAdminPasswd()
    {
        return this.proxyPasswd;
    }

    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("server = ");
        sb.append(server);
        sb.append(" port = ");
        sb.append(port);
        sb.append(" proxyUserDN = ");
        sb.append(proxyUserDN);
        sb.append(" proxyPasswd = ");
        sb.append(proxyPasswd);
        return sb.toString(); 
    }
}
