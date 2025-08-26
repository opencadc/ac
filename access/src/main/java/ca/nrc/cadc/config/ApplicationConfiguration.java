package ca.nrc.cadc.config;

import ca.nrc.cadc.util.StringUtil;

import java.net.URI;

import org.apache.commons.configuration2.CombinedConfiguration;
import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.SystemConfiguration;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.configuration2.tree.MergeCombiner;
import org.apache.log4j.Logger;


public class ApplicationConfiguration {
    private static final Logger LOGGER = Logger.getLogger(ApplicationConfiguration.class);
    private final Configuration configuration;

    public ApplicationConfiguration(final String filePath) {
        final CombinedConfiguration combinedConfiguration = new CombinedConfiguration(new MergeCombiner());

        // Prefer System properties.
        combinedConfiguration.addConfiguration(new SystemConfiguration());

        final Parameters parameters = new Parameters();
        final FileBasedConfigurationBuilder<PropertiesConfiguration> builder =
                new FileBasedConfigurationBuilder<>(PropertiesConfiguration.class).configure(
                        parameters.properties().setFileName(filePath));

        try {
            combinedConfiguration.addConfiguration(builder.getConfiguration());
        } catch (ConfigurationException var5) {
            LOGGER.warn(String.format("No configuration found at %s.\nUsing defaults.", filePath));
        }

        this.configuration = combinedConfiguration;
    }

    /**
     * System property-only configuration.
     */
    public ApplicationConfiguration() {
        this.configuration = new SystemConfiguration();
    }

    public URI lookupServiceURI(String key, URI defaultValue) {
        final String value = this.lookup(key);
        return StringUtil.hasText(value) ? URI.create(value) : defaultValue;
    }

    public int lookupInt(String key, int defaultValue) {
        return configuration.getInt(key, defaultValue);
    }

    public boolean lookupBoolean(String key, boolean defaultValue) {
        return configuration.getBoolean(key, defaultValue);
    }

    public String lookup(String key, String defaultValue) {
        return configuration.getString(key, defaultValue);
    }

    @SuppressWarnings("unchecked")
    public <T> T lookup(String key) {
        return (T) configuration.getProperty(key);
    }


    public String[] lookupAll(String key) {
        return configuration.getStringArray(key);
    }
}
