package org.opencadc.posix.mapper.web;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.IdentityManager;
import org.opencadc.posix.mapper.auth.DelegatingAPIKeyIdentityManager;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;


/**
 * A bit of an ugly hack to reset the IdentityManager with a delegating one.
 */
public class PosixMapperListener implements ServletContextListener {
    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER = AuthenticationUtil.getIdentityManager();
        System.setProperty(IdentityManager.class.getName(), DelegatingAPIKeyIdentityManager.class.getName());
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        // Reset.
        System.setProperty(IdentityManager.class.getName(),
                           DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER.getClass().getName());
        DelegatingAPIKeyIdentityManager.DELEGATED_IDENTITY_MANAGER = null;
    }
}
