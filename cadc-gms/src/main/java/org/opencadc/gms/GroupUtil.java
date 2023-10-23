/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2019.                            (c) 2019.
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

package org.opencadc.gms;

import java.lang.reflect.Constructor;
import java.net.URI;

import org.apache.log4j.Logger;

/**
 * Group Utilities
 * 
 * @author majorb
 *
 */
@Deprecated
public class GroupUtil {
    
    /**
     * Construct a GMS Client from the classpath or fallback to
     * the default, no-op implementation if a GMS Client has not
     * been configured.  Classpath loaded implementations
     * must provide a constructor that takes the service URI as
     * an argument.
     * <p></p>
     * @param serviceID GMS Service ID.  If null, the default no-op
     *      implementation of GMS Client is returned.
     * 
     * @return A GMSClient instance.
     */
    public static GroupClient getGroupClient(URI serviceID) {
        
        Logger log = Logger.getLogger(GroupClient.class);
        
        String defaultImplClass = GroupClient.class.getName() + "Impl";
        String cname = System.getProperty(GroupClient.class.getName());
        Class c = null;
        if (cname == null) {
            cname = defaultImplClass;
        }
        
        if (serviceID != null) {
            try {
                c = Class.forName(cname);
                Constructor con = c.getConstructor(URI.class);
                Object o = con.newInstance(serviceID);
                GroupClient ret = (GroupClient) o;
                log.debug("GMSClient: " + cname);
                return ret;
            } catch (Throwable t) {
                if (!defaultImplClass.equals(cname) || c != null) {
                    log.error("failed to load configured GMSClient: " + cname, t);
                }
                log.debug("failed to load default GMSClient: " + cname, t);
            }
        } else {
            log.debug("null serviceID, using default NoOpGMSClient");
        }
        
        log.debug("GMSClient: " + NoOpGroupClient.class.getName());
        return new NoOpGroupClient();
        
    }

}
