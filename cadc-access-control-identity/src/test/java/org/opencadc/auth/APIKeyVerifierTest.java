package org.opencadc.auth;

import ca.nrc.cadc.auth.NotAuthenticatedException;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;


public class APIKeyVerifierTest {

    @Test
    public void testVerifyNotAuthorized() throws Exception {
        final File testFile = Files.createTempFile("testVerifyNotAuthorized-keys", "txt").toFile();
        try (final BufferedWriter fileWriter = new BufferedWriter(new FileWriter(testFile))) {
            fileWriter.write("KEY1\n");
            fileWriter.write("KEY2\n");
            fileWriter.flush();
        }

        final APIKeyVerifier testSubject = new APIKeyVerifier(testFile);

        try {
            testSubject.verify("bogus");
        } catch (NotAuthenticatedException notAuthenticatedException) {
            // Good!
        }
    }

    @Test
    public void testVerify() throws Exception {
        final File testFile = Files.createTempFile("testVerify-keys", "txt").toFile();
        try (final BufferedWriter fileWriter = new BufferedWriter(new FileWriter(testFile))) {
            fileWriter.write("KEY3\n");
            fileWriter.write("KEY4\n");
            fileWriter.flush();
        }

        final APIKeyVerifier testSubject = new APIKeyVerifier(testFile);
        testSubject.verify("KEY4");
    }
}
