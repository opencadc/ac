/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2021.                            (c) 2021.
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

import ca.nrc.cadc.ac.GroupNotFoundException;
import ca.nrc.cadc.net.TransientException;
import ca.nrc.cadc.util.StringUtil;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.AccessControlException;
import java.util.Iterator;
import java.util.List;
import java.util.PropertyResourceBundle;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.mail.MessagingException;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import org.apache.log4j.Logger;

public class EmailAllUsers extends AbstractCommand {

    private static final Logger log = Logger.getLogger(EmailAllUsers.class);

    private static final String SMTP_CONFIG = "ac-admin-email.properties";

    // sleep time in secs between emails
    private static final int SLEEP_TIME = 10;

    private static final List<String> SMTP_PROPS =
        Stream.of(Mailer.SMTP_HOST, Mailer.SMTP_PORT).collect(Collectors.toList());

    private static final List<String> MAIL_PROPS =
        Stream.of(Mailer.MAIL_FROM, Mailer.MAIL_TO, Mailer.MAIL_REPLY_TO,
                  Mailer.MAIL_SUBJECT, Mailer.MAIL_BODY).collect(Collectors.toList());

    private final String emailPropsFilename;
    private final String logFilename;
    private final int batchSize;
    private final String toGroup;
    private final boolean toAllUsers;
    private final String resumeEmail;
    private final boolean dryRun;

    private PropertyResourceBundle smtpProps;
    private PropertyResourceBundle mailProps;
    private BufferedWriter logWriter;

    public EmailAllUsers(String emailPropsFilename, String logFilename, int batchSize, String toGroup,
                         boolean toAllUsers, String resumeEmail, boolean dryRun)
        throws UsageException {

        this.emailPropsFilename = emailPropsFilename;
        this.logFilename = logFilename;
        this.batchSize = batchSize;
        this.toGroup = toGroup;
        this.toAllUsers = toAllUsers;
        this.resumeEmail = resumeEmail;
        this.dryRun = dryRun;

        init();
    }

    @Override
    protected void doRun()
        throws AccessControlException, TransientException {

        // Get list of emails to send
        SortedSet<String> allEmails;
        try {
            allEmails = getEmails();
        } catch (GroupNotFoundException e) {
            e.printStackTrace();
            throw new IllegalStateException(String.format("unknown group name - %s: %s",this.toGroup, e.getMessage()));
        }

        int total = allEmails.size();
        this.systemOut.printf("emails to process: %s%n", total);
        if (dryRun) {
            this.systemOut.printf("dry run: logging only, no emails will be sent%n");
        }

        // send and log emails in batches of BATCH_SIZE
        Iterator<String> iter = allEmails.iterator();
        SortedSet<String> toSend = new TreeSet<>();
        int batch;
        int skipped = 0;
        int sent = 0;
        boolean done = false;
        while (!done) {
            batch = 0;
            toSend.clear();
            while (iter.hasNext() && batch < this.batchSize) {
                String email = iter.next();
                // remove noise from dev ldap
                if (email.startsWith("CadcAdminIntTestUser")) {
                    skipped++;
                    continue;
                }
                try {
                    boolean strict = true;
                    new InternetAddress(email, strict);
                } catch (AddressException e) {
                    this.systemOut.printf("invalid address - skip: %s%n", email);
                    skipped++;
                    continue;
                }
                toSend.add(email);
                batch++;
            }

            if (toSend.isEmpty()) {
                done = true;
                continue;
            }

            try {
                sendEmails(toSend);
                sent += toSend.size();
                this.systemOut.printf("processed:%s sent:%s skipped:%s total[%s/%s]%n",
                                      toSend.size(), sent, skipped, sent + skipped, allEmails.size());
            } catch (MessagingException e) {
                e.printStackTrace();
                throw new IllegalStateException(String.format("error sending email: %s", e.getMessage()));
            }

            try {
                for (String email : toSend) {
                    this.logWriter.write(email);
                    this.logWriter.newLine();
                }
                this.logWriter.flush();
            } catch (IOException e) {
                throw new IllegalStateException(String.format("Error writing to email log file: %s", e.getMessage()));
            }

            // try to avoid sleeping after last batch of emails
            if (toSend.size() == this.batchSize) {
                try {
                    this.systemOut.printf("sleeping for %s secs%n", SLEEP_TIME);
                    Thread.sleep(SLEEP_TIME * 1000);
                } catch (InterruptedException e) {
                    throw new IllegalStateException(String.format("Error while sleeping: %s", e.getMessage()));
                }
            }
        }
        this.systemOut.printf("  total: %s%n", total);
        this.systemOut.printf("   sent: %s%n", sent);
        this.systemOut.printf("skipped: %s%n", skipped);

        try {
            this.logWriter.close();
        } catch (IOException e) {
            this.systemOut.printf("error closing log file: %s%n", e.getMessage());
        }
    }

    protected void init()
        throws UsageException {
        this.smtpProps = AdminUtil.getProperties(SMTP_CONFIG, SMTP_PROPS);
        this.mailProps = AdminUtil.getProperties(emailPropsFilename, MAIL_PROPS);
        this.logWriter = initLogging(logFilename);
    }

    protected BufferedWriter initLogging(String logFilename)
        throws UsageException {

        Path path = Paths.get(logFilename);
        BufferedWriter writer;
        try {
            writer = Files.newBufferedWriter(path, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UsageException(
                String.format("unable to write to file - %s: %s", logFilename, e.getMessage()));
        }
        return writer;
    }

    protected SortedSet<String> getEmails()
        throws GroupNotFoundException, AccessControlException, TransientException {

        SortedSet<String> emails;
        if (this.toAllUsers) {
            emails = this.getUserPersistence().getEmailsForAllUsers();
        } else if (this.toGroup != null) {
            emails = this.getGroupPersistence().getMemberEmailsForGroup(this.toGroup);
        } else {
            // Shouldn't get here but...
            throw new IllegalStateException("One of --to or --to-all must be given");
        }

        // Check if resuming from given email
        if (StringUtil.hasText(this.resumeEmail)) {
            try {
                emails = emails.tailSet(this.resumeEmail);
                emails.remove(this.resumeEmail);
                this.systemOut.printf("resuming from email %s%n", emails.first());
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(String.format("--resume email %s not found in email list",
                                                                 this.resumeEmail));
            }
        }
        return emails;
    }

    protected void sendEmails(Set<String> emails)
        throws MessagingException {

        if (this.dryRun) {
            return;
        }

        Mailer mailer = new Mailer();
        mailer.setSmtpHost(smtpProps.getString(Mailer.SMTP_HOST));
        mailer.setSmtpPort(smtpProps.getString(Mailer.SMTP_PORT));

        mailer.setToList(new String[] { mailProps.getString(Mailer.MAIL_TO)});
        mailer.setReplyToList(new String[] { mailProps.getString(Mailer.MAIL_REPLY_TO)});
        mailer.setBccList(emails.stream().toArray(String[]::new));
        mailer.setFrom(mailProps.getString(Mailer.MAIL_FROM));
        mailer.setSubject(mailProps.getString(Mailer.MAIL_SUBJECT));
        mailer.setBody(mailProps.getString(Mailer.MAIL_BODY));

        mailer.setContentType(Mailer.HTML_CONTENT_TYPE);

        mailer.doSend();
    }

}
