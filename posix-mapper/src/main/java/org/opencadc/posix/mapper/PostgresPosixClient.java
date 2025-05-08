/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2023.                            (c) 2023.
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
 *
 ************************************************************************
 */

package org.opencadc.posix.mapper;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.hibernate.query.Query;
import org.opencadc.gms.GroupURI;
import org.opencadc.posix.mapper.web.group.GroupWriter;
import org.opencadc.posix.mapper.web.user.UserWriter;


public class PostgresPosixClient implements PosixClient {

    private final Postgres postgres;

    public PostgresPosixClient(Postgres postgres) {
        this.postgres = postgres;
    }

    /**
     * Closes this resource, relinquishing any underlying resources.  This function will close off the Postgres
     * connection, and any related items.
     */
    public void close() {
        if (this.postgres != null) {
            this.postgres.close();
        }
    }

    @Override
    public User getUser(String userId) {
        Map<String, Object> criteria = new HashMap<>();
        criteria.put("username", userId);
        return postgres.find(User.class, "findUserByUsername", criteria);
    }

    @Override
    public User saveUser(User user) {
        return postgres.save(user);
    }

    @Override
    public User updateUser(User user) {
        return postgres.update(user);
    }

    @Override
    public Group getGroup(GroupURI groupURI) {
        Map<String, Object> criteria = new HashMap<>();
        criteria.put("groupURI", groupURI);
        return postgres.find(Group.class, "findGroupByURI", criteria);
    }

    @Override
    public Group saveGroup(Group group) {
        return postgres.save(group);
    }

    @Override
    public void writeUsers(UserWriter writer, String[] usernames, Integer[] uidConstraints) {

        // Ensure GroupURIs are all persisted.
        Arrays.stream(usernames).forEach(username -> {
            final User u = getUser(username);
            if (u == null) {
                postgres.inTransaction(session -> {
                    final User toBePersisted = new User(username);
                    session.persist(toBePersisted);

                    final Group defaultGroup = new Group(new GroupURI(URI.create(PosixClient.DEFAULT_GROUP_AUTHORITY
                            + "?"
                            + toBePersisted.getUsername())));
                    defaultGroup.setGid(toBePersisted.getUid());
                    session.merge(defaultGroup);
                    return Boolean.TRUE;
                });
            }
        });

        final Map<String, Object[]> queryParameters = new HashMap<>();

        postgres.inSession(session -> {
            final StringBuilder queryBuilder = new StringBuilder("from Users u");

            if (usernames.length > 0) {
                queryBuilder.append(" where (u.username in (:usernames))");
                queryParameters.put("usernames", usernames);
            }

            if (uidConstraints.length > 0) {
                if (queryBuilder.indexOf("where") > 0) {
                    queryBuilder.append(" or");
                } else {
                    queryBuilder.append(" where");
                }

                queryBuilder.append(" (u.uid in (:uids))");
                queryParameters.put("uids", uidConstraints);
            }

            final Query<User> userQuery = session.createQuery(queryBuilder.toString(), User.class);
            queryParameters.forEach(userQuery::setParameterList);

            try {
                writer.write(userQuery.stream().iterator());
            } catch (IOException ioException) {
                return Boolean.FALSE;
            }

            return Boolean.TRUE;
        });
    }

    @Override
    public void writeGroups(GroupWriter writer, GroupURI[] groupURIConstraints, Integer[] gidConstraints) {

        // Ensure GroupURIs are all persisted.
        Arrays.stream(groupURIConstraints).forEach(groupURI -> {
            final Group g = getGroup(groupURI);
            if (g == null) {
                saveGroup(new Group(groupURI));
            }
        });

        final Map<String, Object[]> queryParameters = new HashMap<>();

        postgres.inSession(session -> {
            final StringBuilder queryBuilder = new StringBuilder("from Groups g");

            if (groupURIConstraints.length > 0) {
                queryBuilder.append(" where (g.groupURI in (:groupURIs))");
                queryParameters.put("groupURIs", groupURIConstraints);
            }

            if (gidConstraints.length > 0) {
                if (queryBuilder.indexOf("where") > 0) {
                    queryBuilder.append(" or");
                } else {
                    queryBuilder.append(" where");
                }

                queryBuilder.append(" (g.gid in (:gids))");
                queryParameters.put("gids", gidConstraints);
            }

            final Query<Group> groupQuery = session.createQuery(queryBuilder.toString(), Group.class);
            queryParameters.forEach(groupQuery::setParameterList);

            try {
                writer.write(groupQuery.stream().iterator());
            } catch (IOException ioException) {
                return Boolean.FALSE;
            }

            return Boolean.TRUE;
        });
    }
}
