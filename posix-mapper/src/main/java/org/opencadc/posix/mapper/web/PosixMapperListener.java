package org.opencadc.posix.mapper.web;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.IdentityManager;
import org.apache.log4j.Logger;
import org.opencadc.posix.mapper.auth.DelegatingAPIKeyIdentityManager;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;


/**
 * A bit of an ugly hack to reset the IdentityManager with a delegating one.
 */
public class PosixMapperListener implements ServletContextListener {
    public static final Logger LOGGER = Logger.getLogger(PosixMapperListener.class);

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        LOGGER.debug("contextInitialized: START");
        DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER = AuthenticationUtil.getIdentityManager();
        System.setProperty(IdentityManager.class.getName(), DelegatingAPIKeyIdentityManager.class.getName());
        LOGGER.debug("contextInitialized (IdentityManager now set to "
                             + System.getProperty(IdentityManager.class.getName()) + "): OK");
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        LOGGER.debug("contextDestroyed: START");
        // Reset.
        System.setProperty(IdentityManager.class.getName(),
                           DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER.getClass().getName());
        DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER = null;
        LOGGER.debug("contextDestroyed: OK");
    }
}
