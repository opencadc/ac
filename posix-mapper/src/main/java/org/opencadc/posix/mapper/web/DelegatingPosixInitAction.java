package org.opencadc.posix.mapper.web;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.IdentityManager;
import org.apache.log4j.Logger;
import org.opencadc.posix.mapper.auth.DelegatingAPIKeyIdentityManager;


/**
 * Special InitAction class for performing an application-wide one-time operation.  Ensure it's only configured on ONE servlet!
 */
public class DelegatingPosixInitAction extends PosixInitAction {
    private static final Logger LOGGER = Logger.getLogger(DelegatingPosixInitAction.class);

    private static void delegateIdentityManager() {
        LOGGER.debug("delegateIdentityManager: START");
        DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER = AuthenticationUtil.getIdentityManager();
        System.setProperty(IdentityManager.class.getName(), DelegatingAPIKeyIdentityManager.class.getName());
        LOGGER.debug("delegateIdentityManager (IdentityManager now set to " + System.getProperty(IdentityManager.class.getName()) + "): OK");
    }

    private static void resetIdentityManager() {
        LOGGER.debug("resetIdentityManager: START");
        // Reset.
        System.setProperty(IdentityManager.class.getName(), DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER.getClass().getName());
        DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER = null;
        LOGGER.debug("resetIdentityManager: OK");
    }

    @Override
    public void doInit() {
        super.doInit();
        DelegatingPosixInitAction.delegateIdentityManager();
    }

    @Override
    public void doShutdown() {
        super.doShutdown();
        DelegatingPosixInitAction.resetIdentityManager();
    }
}
