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

package org.opencadc.ac;

import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.util.MultiValuedProperties;
import ca.nrc.cadc.util.PropertiesReader;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;

public class GroupsConfig {
    private static final Logger log = Logger.getLogger(GroupsConfig.class);

    // config keys
    private static final String GROUPS_KEY = "org.opencadc.ac";
    static final String RESOURCE_ID = GROUPS_KEY + ".resourceID";
    private static final String PRIVILEGED_X500_PRINCIPALS = GROUPS_KEY + ".privilegedX500Principals";
    private static final String PRIVILEGED_HTTP_PRINCIPALS = GROUPS_KEY + ".privilegedHttpPrincipals";

    private final MultiValuedProperties configProperties;
    private final List<Subject> privilegedSubjects = new ArrayList<>();
    private final URI resourceID;

    public GroupsConfig() {
        PropertiesReader r = new PropertiesReader("ac.properties");
        this.configProperties = r.getAllProperties();
        List<String> resourceIdProp = configProperties.getProperty(RESOURCE_ID);
        if (resourceIdProp.isEmpty()) {
            throw new RuntimeException("Init exception: Missing required property: " + RESOURCE_ID);
        }
        this.resourceID = URI.create(resourceIdProp.get(0));
        initPrivilegedUsers();
    }

    private void initPrivilegedUsers() {
        List<String> x500Users = configProperties.getProperty(PRIVILEGED_X500_PRINCIPALS);
        List<String> httpUsers = configProperties.getProperty(PRIVILEGED_HTTP_PRINCIPALS);

        if (!x500Users.isEmpty() || !httpUsers.isEmpty()) {
            if (x500Users.size() != httpUsers.size()) {
                throw new RuntimeException("Init exception: Lists of augment subject principals not equivalent in length");
            }

            for (int i = 0; i < x500Users.size(); i++) {
                Subject s = new Subject();
                s.getPrincipals().add(new X500Principal(x500Users.get(i)));
                s.getPrincipals().add(new HttpPrincipal(httpUsers.get(i)));
                privilegedSubjects.add(s);
            }
        }
    }

    public URI getResourceID() {
        return resourceID;
    }

    public List<Subject> getPrivilegedSubjects() {
        return privilegedSubjects;
    }
}
