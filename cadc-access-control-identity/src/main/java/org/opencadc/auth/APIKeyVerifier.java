package org.opencadc.auth;

import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.util.StringUtil;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Simple verifier for registering keys and validating provided ones.  This is a very simple implementation that other
 * APIs can use.
 */
public class APIKeyVerifier {
    // Used by callers to pull the key from a Request Header.
    public static final String API_KEY_REQUEST_HEADER_NAME = "X-Client-API-Key";

    // Default location of the file containing keys if none specified.
    public static final File DEFAULT_KEY_FILE = new File(System.getProperty("user.home") + "/config/keys/.api-key");

    // Allowed keys.
    private final List<String> apiKeys = new ArrayList<>();

    /**
     * Constructor.  Set the file name in the config directory to read in.
     */
    public APIKeyVerifier() {
        this(APIKeyVerifier.DEFAULT_KEY_FILE);
    }

    public APIKeyVerifier(final File configFile) {
        if (configFile == null || !configFile.canRead()) {
            throw new IllegalStateException("Must supply a filename at " + configFile
                                            + " containing the verification token.");
        }

        loadKeys(configFile);
    }

    void loadKeys(final File configFile) {
        try (final BufferedReader fileReader = new BufferedReader(new FileReader(configFile))) {
            String line;
            while ((line = fileReader.readLine()) != null) {
                apiKeys.add(line);
            }
        } catch (IOException fileIOException) {
            // File cannot be read.
            throw new IllegalArgumentException(fileIOException.getMessage(), fileIOException);
        }
    }

    /**
     * Verify the provided key with the known list of DNs.
     * @param apiKey   The API Key string to verify.
     * @throws NotAuthenticatedException    If the provided key is not allowed.
     */
    public void verify(final String apiKey) {
        if (!StringUtil.hasText(apiKey) || !apiKeys.contains(apiKey)) {
            throw new NotAuthenticatedException("Key '" + apiKey + "' not authorized.");
        }
    }
}
