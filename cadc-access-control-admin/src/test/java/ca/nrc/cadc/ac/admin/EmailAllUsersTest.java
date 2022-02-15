/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2020.                            (c) 2020.
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
 *  : 5 $
 *
 ************************************************************************
 */

package ca.nrc.cadc.ac.admin;

import ca.nrc.cadc.net.TransientException;
import java.util.ArrayList;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.Assert;
import org.junit.Test;

public class EmailAllUsersTest {

    @Test
    public void getEmailsAllSkipDomainTest() throws Exception {

        EmailAllUsers testSubject = new EmailAllUsers(null, null, 3, null,
                                                      true, null, true) {
            @Override
            protected void init() throws UsageException {}

            @Override
            protected List<String> getSkipDomains() {
                return Stream.of("foo.com", "bar.com").collect(Collectors.toList());
            }

            @Override
            protected SortedSet<String> getAllUserEmails() throws TransientException {
                return Stream.of("foo@foo.com", "bar@bar.com", "baz@baz.bar.com")
                    .collect(Collectors.toCollection(TreeSet::new));
            }
        };

        SortedSet<String> emails = testSubject.getEmails();
        Assert.assertTrue(emails.isEmpty());
    }

    @Test
    public void getEmailsNoSkipDomainTest() throws Exception {

        EmailAllUsers testSubject = new EmailAllUsers(null, null, 3, null,
                                                      true, null, true) {
            @Override
            protected void init() throws UsageException {}

            @Override
            protected List<String> getSkipDomains() {
                return Stream.of("foo.com", "bar.com").collect(Collectors.toList());
            }

            @Override
            protected SortedSet<String> getAllUserEmails() throws TransientException {
                return Stream.of("foo@example.com", "bar@example.com", "baz@example.com")
                    .collect(Collectors.toCollection(TreeSet::new));
            }
        };

        SortedSet<String> emails = testSubject.getEmails();
        Assert.assertFalse(emails.isEmpty());
        Assert.assertEquals(3, emails.size());
    }

    @Test
    public void getEmailsWithSkipDomainTest() throws Exception {

        EmailAllUsers testSubject = new EmailAllUsers(null, null, 3, null,
                                                      true, null, true) {
            @Override
            protected void init() throws UsageException {}

            @Override
            protected List<String> getSkipDomains() {
                return Stream.of("foo.com", "bar.com").collect(Collectors.toList());
            }

            @Override
            protected SortedSet<String> getAllUserEmails() throws TransientException {
                return Stream.of("foo@example.com", "bar@bar.com", "baz@example.com")
                    .collect(Collectors.toCollection(TreeSet::new));
            }
        };

        SortedSet<String> emails = testSubject.getEmails();
        Assert.assertFalse(emails.isEmpty());
        Assert.assertEquals(2, emails.size());
        Assert.assertFalse(emails.contains("bar@cadc.nrc.ca"));
    }

    @Test
    public void getEmailsResume() throws Exception {

        EmailAllUsers testSubject = new EmailAllUsers(null, null, 3, null,
                                                      true, "bar@example.com", true) {
            @Override
            protected void init() throws UsageException {}

            @Override
            protected List<String> getSkipDomains() {
                return new ArrayList<>();
            }

            @Override
            protected SortedSet<String> getAllUserEmails() throws TransientException {
                return Stream.of("bar@bar.com", "baz@baz.bar.com", "foo@foo.com")
                    .collect(Collectors.toCollection(TreeSet::new));
            }
        };

        SortedSet<String> emails = testSubject.getEmails();
        Assert.assertFalse(emails.isEmpty());
        Assert.assertEquals(2, emails.size());

        testSubject = new EmailAllUsers(null, null, 3, null,
                                        true, "baz@example.com", true) {
            @Override
            protected void init() throws UsageException {}

            @Override
            protected List<String> getSkipDomains() {
                return new ArrayList<>();
            }

            @Override
            protected SortedSet<String> getAllUserEmails() throws TransientException {
                return Stream.of("bar@example.com", "baz@example.com", "foo@example.com")
                    .collect(Collectors.toCollection(TreeSet::new));
            }
        };

        emails = testSubject.getEmails();
        Assert.assertFalse(emails.isEmpty());
        Assert.assertEquals(1, emails.size());

        testSubject = new EmailAllUsers(null, null, 3, null,
                                        true, "foo@example.com", true) {
            @Override
            protected void init() throws UsageException {}

            @Override
            protected List<String> getSkipDomains() {
                return new ArrayList<>();
            }

            @Override
            protected SortedSet<String> getAllUserEmails() throws TransientException {
                return Stream.of("bar@example.com", "baz@example.com", "foo@example.com")
                    .collect(Collectors.toCollection(TreeSet::new));
            }
        };

        emails = testSubject.getEmails();
        Assert.assertTrue(emails.isEmpty());
    }

}
