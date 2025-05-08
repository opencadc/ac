package ca.nrc.cadc.ac.admin;

import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.spi.InitialContextFactory;

/**
 * A Simple ContextFactory.
 */
public class ContextFactoryImpl implements InitialContextFactory {

    public ContextFactoryImpl() {
    }

    @Override
    public Context getInitialContext(Hashtable environment)
            throws NamingException {
        return new ContextImpl();
    }

}
