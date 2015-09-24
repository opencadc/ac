/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2015.                            (c) 2015.
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

import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;

import org.apache.log4j.Logger;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;

import ca.nrc.cadc.profiler.Profiler;

/**
 * Class that provides access to the LdapConnectionPool through
 * JNDI binding.
 */
public class LdapPersistence
{
    private static final Logger logger = Logger.getLogger(LdapPersistence.class);
    private static final String LDAP_POOL_JNDI_NAME = LdapConnectionPool.class.getName();

    Profiler profiler = new Profiler(LdapPersistence.class);

    private LdapConnectionPool pool;
    private static Object jndiMonitor = new Object();

    LdapPersistence()
    {
        initPool();
    }

    protected LDAPConnection getReadOnlyConnection() throws LDAPException
    {
        return pool.getReadOnlyConnection();
    }

    protected LDAPConnection getReadWriteConnection() throws LDAPException
    {
        return pool.getReadWriteConnection();
    }

    protected void releaseReadOnlyConnection(LDAPConnection conn)
    {
        pool.releaseReadOnlyConnection(conn);
    }

    protected void releaseReadWriteConnection(LDAPConnection conn)
    {
        pool.releaseReadWriteConnection(conn);
    }

    protected LdapConfig getCurrentConfig()
    {
        return pool.currentConfig;
    }

    protected void shutdown()
    {
        // shutdown the pool
        pool.shutdown();

        // unbind the pool
        try
        {
            InitialContext ic = new InitialContext();
            ic.unbind(LDAP_POOL_JNDI_NAME);
        }
        catch (NamingException e)
        {
            logger.warn("Could not unbind ldap pool", e);
        }
    }

    private void initPool()
    {
        try
        {
            pool = lookupPool();
            logger.debug("Pool from JNDI lookup: " + pool);

            if (pool == null)
            {
                synchronized (jndiMonitor)
                {
                    pool = lookupPool();
                    logger.debug("Pool from second JNDI lookup: " + pool);
                    if (pool == null)
                    {
                        pool = new LdapConnectionPool();
                        profiler.checkpoint("Created LDAP connection pool");
                        InitialContext ic = new InitialContext();
                        ic.bind(LDAP_POOL_JNDI_NAME, pool);
                        profiler.checkpoint("Bound LDAP pool to JNDI");
                        logger.debug("Bound LDAP pool to JNDI");
                    }
                }
            }
        }
        catch (Throwable t)
        {
            String message = "Failed to find or create LDAP connection pool: " + t.getMessage();
            throw new IllegalStateException(message, t);
        }
    }

    private LdapConnectionPool lookupPool() throws NamingException
    {
        try
        {
            InitialContext ic = new InitialContext();
            return (LdapConnectionPool) ic.lookup(LDAP_POOL_JNDI_NAME);
        }
        catch (NameNotFoundException e)
        {
            return null;
        }
    }

}
