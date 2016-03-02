/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2011.                            (c) 2011.
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
*  $Revision: 5 $
*
************************************************************************
*/

package ca.nrc.cadc.ac.client;

import ca.nrc.cadc.ac.Group;
import ca.nrc.cadc.ac.Role;
import org.apache.log4j.Logger;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class used to hold list of groups in which a user is known to be a member.
 * 
 * @author pdowler
 */
public class GroupMemberships implements Comparable
{
    private static final Logger log = Logger.getLogger(GroupMemberships.class);

    private Principal userID;
    private Map<Role, List<Group>> memberships = new HashMap<Role, List<Group>>();
    private Map<Role, Boolean> complete = new HashMap<Role, Boolean>();

    public GroupMemberships() { init(); }
    
    public GroupMemberships(Principal userID)
    {
        this.userID = userID;
        init();
    }
    
    public boolean isComplete(Role role)
    {
        return complete.get(role);
    }
    
    public List<Group> getMemberships(Role role)
    {
        return memberships.get(role);
    }
    
    private void init()
    {
        for (Role role : Role.values())
        {
            complete.put(role, Boolean.FALSE);
            memberships.put(role, new ArrayList<Group>());
        }
    }

    public Principal getUserID()
    {
        return userID;
    }
    
    public void add(Group group, Role role)
    {
        List<Group> groups = memberships.get(role);
        if (!groups.contains(group))
            groups.add(group);
    }
    
    public void add(List<Group> groups, Role role)
    {
        List<Group> cur = memberships.get(role);
        for (Group group : groups)
        {
            if (!cur.contains(group))
                cur.add(group);
            complete.put(role, Boolean.TRUE);
        }
    }
    
    // only allow one in a set - makes clearCache simple too
    public boolean equals(Object rhs)
    {
        if (rhs != null && rhs instanceof GroupMemberships)
            return true;
        return false;
    }

    public int compareTo(Object t)
    {
        if (this.equals(t))
            return 0;
        return -1; // wonder if this is sketchy
    }
}
