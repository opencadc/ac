package ca.nrc.cadc.accesscontrol;

import ca.nrc.cadc.config.ApplicationConfiguration;
import ca.nrc.cadc.util.StringUtil;

import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;


public class AccessControlUtil {

    private static final Logger LOG = Logger.getLogger(AccessControlUtil.class);
    public static final String SSO_COOKIE_NAME = "CADC_SSO";
    static final String SSO_SERVERS_KEY = "SSO_SERVERS";
    static final String COOKIE_DOMAINS_KEY = "COOKIE_DOMAINS";
    public static final String SSO_COOKIE_LIFETIME_SECONDS_KEY = "SSO_TOKEN_LIFETIME_SECONDS";
    public static final String DEFAULT_AC_PROPERTIES_FILE_PATH =
            System.getProperty("user.home") + "/config/AccessControl.properties";
    public static final int DEFAULT_COOKIE_LIFETIME_SECONDS = 48 * 60 * 60; // 48 hours
    private final ApplicationConfiguration applicationConfiguration;


    public AccessControlUtil(ApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
    }

    /**
     * Load from the given file path as well as the System properties.
     *
     * @param filePath Path to a known configuration file.
     */
    public AccessControlUtil(final String filePath) {
        this(new ApplicationConfiguration(filePath));
    }

    /**
     * Load from the default file path.
     */
    public AccessControlUtil() {
        this(DEFAULT_AC_PROPERTIES_FILE_PATH);
    }


    private Set<String> addServers(String hostsString) {
        final Set<String> servers = new HashSet<>();

        if (StringUtil.hasText(hostsString)) {
            final String[] hosts = hostsString.split(" ");

            for (final String host : hosts) {
                if (StringUtil.hasLength(host)) {
                    servers.add(host);
                }
            }
        }

        return servers;
    }

    public Set<String> getCookieDomains() {
        final String hostsString = applicationConfiguration.lookup(COOKIE_DOMAINS_KEY);
        return addServers(hostsString);
    }

    public Set<String> getSSOServers() {
        final String hostsString = applicationConfiguration.lookup(SSO_SERVERS_KEY);
        return addServers(hostsString);
    }

    public int getCookieLifetimeSeconds() {
        return applicationConfiguration.lookupInt(AccessControlUtil.SSO_COOKIE_LIFETIME_SECONDS_KEY,
                                                  AccessControlUtil.DEFAULT_COOKIE_LIFETIME_SECONDS);
    }
}
