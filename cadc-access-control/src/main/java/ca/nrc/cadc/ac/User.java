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

import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.PrincipalComparator;
import java.security.Principal;
import java.util.Comparator;
import java.util.Date;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import javax.security.auth.x500.X500Principal;

public class User {
    private InternalID id;

    private SortedSet<Principal> identities;

    public PersonalDetails personalDetails;
    public PosixDetails posixDetails;

    public Date lastModified;

    /**
     * Applications can stash some extra stuff here.
     */
    public Object appData;

    public User() {
        PrincipalComparator p = new PrincipalComparator();
        UserPrincipalComparator u = new UserPrincipalComparator(p);
        this.identities = new TreeSet<Principal>(Comparator.nullsLast(u));
    }

    public InternalID getID() {
        return id;
    }

    public Set<Principal> getIdentities() {
        return identities;
    }

    /*
    * Obtain a set of identities whose type match the given one.
    *
    * @param identityClass The class to search on.
    * @param <S>           The Principal type.
    * @return Set of matched identities, or empty Set.
    * Never null.
    */
    public <S extends Principal> Set<S> getIdentities(final Class<S> identityClass) {
        PrincipalComparator p = new PrincipalComparator();
        UserPrincipalComparator u = new UserPrincipalComparator(p);
        final Set<S> matchedIdentities = new TreeSet<S>(u);

        for (final Principal principal : identities) {
            if (identityClass.isAssignableFrom(principal.getClass())) {
                matchedIdentities.add((S) principal);
            }
        }

        return matchedIdentities;
    }

    public HttpPrincipal getHttpPrincipal() {
        Set<HttpPrincipal> identities = getIdentities(HttpPrincipal.class);
        if (!identities.isEmpty()) {
            return identities.iterator().next();
        }
        return null;
    }

    /**
     * @deprecated
     */
    public X500Principal getX500Principal() {
        final Set<X500Principal> identities =
                getIdentities(X500Principal.class);
        if (!identities.isEmpty()) {
            return identities.iterator().next();
        }
        return null;
    }


    /**
     * A User is considered consistent if the User's set of identities are a superset
     * of this Users set of identities.
     *
     * @param superset
     * @return true if the user is consistent, false otherwise
     */
    public boolean isConsistent(final User superset) {

        if (superset == null) {
            return false;
        }

        if (this.identities.size() == 0 || superset.identities.size() == 0) {
            return false;
        }

        PrincipalComparator p = new PrincipalComparator();
        TreeSet<Principal> set1 = new TreeSet<Principal>(p);
        TreeSet<Principal> set2 = new TreeSet<Principal>(p);
        set1.addAll(superset.getIdentities());
        set2.addAll(this.getIdentities());
        return set1.containsAll(set2);
    }


    /*
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof User) {
            User user = (User) obj;
            return (this.isConsistent(user) || user.isConsistent(this));
        }
        return false;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append("[");
        if (id != null) {
            sb.append(id);
        }
        sb.append("]");
        return sb.toString();
    }

    public String toPrettyString() {
        HttpPrincipal p1 = this.getHttpPrincipal();
        if (p1 != null) {
            return p1.getName();
        }
        X500Principal p2 = this.getX500Principal();
        if (p2 != null) {
            return p2.getName();
        }
        return toString();
    }

    private class UserPrincipalComparator implements Comparator<Principal> {
        private PrincipalComparator principalComparator;

        UserPrincipalComparator(PrincipalComparator p) {
            this.principalComparator = p;
        }

        @Override
        public int compare(Principal o1, Principal o2) {
            if (o1 == null || o2 == null) {
                throw new IllegalArgumentException("Cannot compare null objects");
            }

            if (o1 instanceof HttpPrincipal && o2 instanceof HttpPrincipal) {
                return 0;
            }

            return principalComparator.compare(o1, o2);
        }
    }

}
