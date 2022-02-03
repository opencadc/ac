/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2005.                            (c) 2005.
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits reserves
 *
 * NRC disclaims any warranties         Le CNRC denie toute garantie
 * expressed, implied, or statu-        enoncee, implicite ou legale,
 * tory, of any kind with respect       de quelque nature que se soit,
 * to the software, including           concernant le logiciel, y com-
 * without limitation any war-          pris sans restriction toute
 * ranty of merchantability or          garantie de valeur marchande
 * fitness for a particular pur-        ou de pertinence pour un usage
 * pose.  NRC shall not be liable       particulier.  Le CNRC ne
 * in any event for any damages,        pourra en aucun cas etre tenu
 * whether direct or indirect,          responsable de tout dommage,
 * special or general, consequen-       direct ou indirect, particul-
 * tial or incidental, arising          ier ou general, accessoire ou
 * from the use of the software.        fortuit, resultant de l'utili-
 *                                      sation du logiciel.
 *
 *
 * @author adriand
 *
 * @version $Revision$
 *
 *
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.ac.admin;


import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import ca.nrc.cadc.util.StringUtil;

import java.util.Properties;

import org.apache.log4j.Logger;


/**
 * <code><b>Mailer</b></code> is a very simple utility class for sending SMTP
 * email. At the very least, all that a client needs to do to send email is to
 * invoke the static <code><b>send</b></code> method:
 * <p>
 * <b><code>
 * Mailer.send(toList, ccList, bccList, replyToList, from, subject, text);
 *  </b></code>
 * </p>
 * <p>
 * Note that the class requires the <code><b>mail.smtp.host</b></code> system
 * propriety to be set to the name of the smtp server
 * <p>
 * Note 2: When the <code><b>unitTest</b></code> system property is set at this
 * class level (e.g.: <code><b>ca.nrc.cadc.util.mail.Mailer.unitTest</b></code>)
 * or at the package level (e.g.: <code><b>ca.nrc.cadc.unitTest</b></code> or
 * <code><b>ca.nrc.cadc.util.mail.unitTest</b></code>) the send method performs
 * all the normal execution steps EXCEPT the actual dispatch of the message.
 * This kind of behaviour is useful during the unit testing of the clients when
 * the email messages are not required to be sent out.
 *
 */
public class Mailer {
    private static Logger logger = Logger.getLogger(Mailer.class);

    public static final String DEFAULT_CONTENT_TYPE = "text/plain";
    public static final String HTML_CONTENT_TYPE = "text/html; charset=utf-8";

    public static final String SMTP_HOST = "smtp.host";
    public static final String SMTP_PORT = "smtp.port";

    public static final String SMTP_AUTH_HOST = "smtp.auth.host";
    public static final String SMTP_AUTH_PORT = "smtp.auth.port";
    public static final String SMTP_ACCOUNT = "smtp.account";
    public static final String SMTP_PASSWORD = "smtp.password";

    public static final String MAIL_FROM = "mail.from";
    public static final String MAIL_TO = "mail.to";
    public static final String MAIL_REPLY_TO = "mail.reply-to";
    public static final String MAIL_BCC = "mail.bcc";
    public static final String MAIL_SUBJECT = "mail.subject";
    public static final String MAIL_BODY = "mail.body";

    public static final String MAIL_CONFIG = "ac-admin-email.properties";
    public static final String MAIL_SKIP_DOMAINS = "mail.skip-domains";

    // sleep time in secs between emails
    public static final int SLEEP_TIME = 10;

    protected Session session; // java mail session object

    protected String from; // sender's mail address

    protected String subject; // subject of the message

    protected String body; // text of the message

    // Content type of the body text.  Plain text by default.
    protected String contentType = DEFAULT_CONTENT_TYPE;

    // recipient, cc and bcc lists
    protected String[] toList;

    protected String[] ccList;

    protected String[] bccList;

    // reply to list
    protected String[] replyToList;

    protected String smtpHost;
    protected String smtpPort;
    protected String smtpAccount;
    protected String smtpPassword;

    public boolean isComplete(boolean authenticated)
    {
        if (from == null || from.length() == 0)
        {
            logger.error("No from field set in Mailer");
            return false;
        }

        if (toList == null || toList.length == 0)
        {
            logger.error("Empty \"to\" list in Mailer");
            return false;
        }

        if (subject == null || subject.length() == 0)
        {
            logger.error("No subject field set in Mailer");
            return false;
        }

        if (body == null || body.length() == 0)
        {
            logger.error("No message body set in Mailer");
            return false;
        }

        if (smtpHost == null || smtpHost.length() == 0) {
            logger.error("No SMTP host set in Mailer");
            return false;
        }

        if (smtpPort == null || smtpPort.length() == 0) {
            logger.error("No SMTP port set in Mailer");
            return false;
        }

        if (authenticated) {
            if (smtpAccount == null || smtpAccount.length() == 0) {
                logger.error("No SMTP account set in Mailer");
                return false;
            }

            if (smtpPassword == null || smtpPassword.length() == 0) {
                logger.error("No SMTP password set in Mailer");
                return false;
            }
        }

        return true;
    }

    /**
     * Method to send an email message.
     *
     * @param authenticated Whether to use the auth SMTP server or not.
     * @throws MessagingException Email problems
     * @throws IllegalArgumentException when the object is not initialized properly.
     */
    public synchronized void doSend(boolean authenticated) throws MessagingException
    {
        if (!isComplete(authenticated))
        {
            throw new IllegalArgumentException(
                "doSend called before message was complete");
        }

        Properties props = new Properties();
        props.put("mail.smtp.port", smtpPort);
        props.put("mail.smtp.host", smtpHost);
        if (authenticated) {
            props.put("mail.smtp.account", smtpAccount);
            props.put("mail.smtp.password", smtpPassword);
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", true);
        }

        if (session == null)
        {
            session = Session.getInstance(props);
        }

        // create a message
        final Message msg = new MimeMessage(session);

        // TO address list
        InternetAddress[] addresses = new InternetAddress[toList.length];
        for (int i = 0; i < addresses.length; i++)
        {
            addresses[i] = new InternetAddress(toList[i]);
            logger.debug("added TO email address: " + addresses[i]);
        }
        msg.setRecipients(Message.RecipientType.TO, addresses);

        msg.setFrom(new InternetAddress(from));
        logger.debug("set FROM: " + from);
        if(replyToList != null)
        {
            addresses = new InternetAddress[replyToList.length];
            for (int i = 0; i < addresses.length; i++)
            {
                addresses[i] = new InternetAddress(replyToList[i]);
                logger.debug("added REPLY-TO email address: " + addresses[i]);
            }
            msg.setReplyTo(addresses);
        }

        // CC address list
        if (ccList != null)
        {
            addresses = new InternetAddress[ccList.length];
            for (int i = 0; i < addresses.length; i++)
            {
                addresses[i] = new InternetAddress(ccList[i]);
                logger.debug("added CC email address: " + addresses[i]);
            }
            msg.setRecipients(Message.RecipientType.CC, addresses);
        }

        // BCC address list
        if (bccList != null)
        {
            addresses = new InternetAddress[bccList.length];
            for (int i = 0; i < addresses.length; i++)
            {
                addresses[i] = new InternetAddress(bccList[i]);
                logger.debug("added BCC email address: " + addresses[i]);
            }
            msg.setRecipients(Message.RecipientType.BCC, addresses);
        }

        msg.setSubject(subject);
        logger.debug("set subject: " + subject);

        // Just in case the content type was set to null for some reason...
        msg.setContent(body, StringUtil.hasText(contentType) ? contentType : DEFAULT_CONTENT_TYPE);
        logger.debug("set body: " + body);
        logger.debug("contentType: " + (StringUtil.hasText(contentType) ? contentType : DEFAULT_CONTENT_TYPE));

        logger.debug("sending email");
        if (authenticated) {
            Transport.send(msg, smtpAccount, smtpPassword);
        } else {
            Transport.send(msg);
        }
    }

    /**
     * Convenience method to send email
     *
     * @param recipient
     *            recipient(s) of the message. Cannot be null.
     * @param cc
     *            cc list. Can be null.
     * @param bcc
     *            bcc list. Can be null.
     * @param sender
     *            the sender of the message. Cannot be null.
     * @param replyTo
     *            addresses to be used for reply. Can be null.
     * @param subject
     *            the subject of the message. Cannot be null.
     * @param message
     *            the body of the message. Cannot be null.
     * @return true if message successfully send, or false otherwise (log
     *         message details the cause of the failure).
     */
    public static boolean send(String[] recipient, String[] cc, String[] bcc,
                               String sender, String[] replyTo, String subject, String message, boolean authenticated)
    {
        Mailer mailer = new Mailer();
        mailer.toList = recipient;
        mailer.ccList = cc;
        mailer.bccList = bcc;
        mailer.from = sender;
        mailer.replyToList = replyTo;
        mailer.subject = subject;
        mailer.body = message;
        try
        {
            mailer.doSend(authenticated);
        }
        catch (MessagingException e)
        {
            logger.error("Problems sending email message: ", e);
            return false;
        }
        return true;
    }

    /**
     * @return Returns the bccList.
     */
    public String[] getBccList()
    {
        return bccList;
    }

    /**
     * @param bccList
     *            The bccList to set.
     */
    public void setBccList(String[] bccList)
    {
        this.bccList = bccList;
    }

    /**
     * @return Returns the body.
     */
    public String getBody()
    {
        return body;
    }

    /**
     * @param body
     *            The body to set.
     */
    public void setBody(String body)
    {
        this.body = body;
    }

    public void setContentType(final String contentType)
    {
        this.contentType = contentType;
    }

    /**
     * @return Returns the ccList.
     */
    public String[] getCcList()
    {
        return ccList;
    }

    /**
     * @param ccList
     *            The ccList to set.
     */
    public void setCcList(String[] ccList)
    {
        this.ccList = ccList;
    }

    /**
     * @return Returns the from.
     */
    public String getFrom()
    {
        return from;
    }

    /**
     * @param from
     *            The from to set.
     */
    public void setFrom(String from)
    {
        this.from = from;
    }

    /**
     * @return Returns the subject.
     */
    public String getSubject()
    {
        return subject;
    }

    /**
     * @param subject
     *            The subject to set.
     */
    public void setSubject(String subject)
    {
        this.subject = subject;
    }

    /**
     * @return Returns the toList.
     */
    public String[] getToList()
    {
        return toList;
    }

    /**
     * @param toList
     *            The toList to set.
     */
    public void setToList(String[] toList)
    {
        this.toList = toList;
    }

    /**
     * @return Returns the replyTo list.
     */
    public String[] getReplyToList()
    {
        return replyToList;
    }

    /**
     * @param replyToList
     *            The replyTo list to set.
     */
    public void setReplyToList(String[] replyToList)
    {
        this.replyToList = replyToList;
    }

    public void setSmtpHost(String smtpHost) {
        this.smtpHost = smtpHost;
    }

    public void setSmtpPort(String smtpPort) {
        this.smtpPort = smtpPort;
    }

    public void setSmtpAccount(String smtpAccount) {
        this.smtpAccount = smtpAccount;
    }

    public void setSmtpPassword(String smtpPassword) {
        this.smtpPassword = smtpPassword;
    }


}
