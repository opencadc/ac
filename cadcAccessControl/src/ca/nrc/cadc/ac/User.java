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
package ca.nrc.cadc.ac;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import ca.nrc.cadc.auth.AuthenticationUtil;

public class User<T extends Principal>
{
    private T userID;
    
    private Set<Principal> identities = new HashSet<Principal>();

    public Set<UserDetails> details = new HashSet<UserDetails>();
    
    /**
     * Applications can stash some extra stuff here.
     */
    public Object appData;
    
    public User(final T userID)
    {
        if (userID == null)
        {
            throw new IllegalArgumentException("null userID");
        }
        this.userID = userID;
        identities.add(userID);
    }

    public Set<Principal> getIdentities()
    {
        return identities;
    }

    public T getUserID()
    {
        return userID;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        int prime = 31;
        int result = 1;
        result = prime * result + userID.hashCode();
        return result;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (obj == null)
        {
            return false;
        }
        if (getClass() != obj.getClass())
        {
            return false;
        }

        final User other = (User) obj;
        if (userID instanceof X500Principal)
        {
            return AuthenticationUtil.equals(userID, other.userID);
        }
        else
        {
            return userID.equals(other.userID);
        }
    }

    @Override
    public String toString()
    {
        return getClass().getSimpleName() + "[" + userID.getName() + "]";
    }

    public <S extends UserDetails>S getUserDetail(final Class<S> userDetailsClass)
    {
        for (final UserDetails ud : details)
        {
            if (ud.getClass() == userDetailsClass)
            {
                return (S) ud;
            }
        }
        return null;
    }

    public <S extends UserDetails> Set<S> getDetails(
            final Class<S> userDetailsClass)
    {
        final Set<S> matchedDetails = new HashSet<S>();

        for (final UserDetails ud : details)
        {
            if (ud.getClass() == userDetailsClass)
            {
                // This casting shouldn't happen, but it's the only way to
                // do this without a lot of work.
                // jenkinsd 2014.09.26
                matchedDetails.add((S) ud);
            }
        }

        return matchedDetails;
    }

    /**
     * Obtain a set of identities whose type match the given one.
     *
     * @param identityClass     The class to search on.
     * @param <S>               The Principal type.
     * @return                  Set of matched identities, or empty Set.
     *                          Never null.
     */
    public <S extends Principal> Set<S> getIdentities(
            final Class<S> identityClass)
    {
        final Set<S> matchedIdentities = new HashSet<S>();

        for (final Principal p : identities)
        {
            if (p.getClass() == identityClass)
            {
                // This casting shouldn't happen, but it's the only way to
                // do this without a lot of work.
                // jenkinsd 2014.09.26
                matchedIdentities.add((S) p);
            }
        }

        return matchedIdentities;
    }
}
