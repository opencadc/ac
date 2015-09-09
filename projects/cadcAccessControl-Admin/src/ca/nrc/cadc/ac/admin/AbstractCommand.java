package ca.nrc.cadc.ac.admin;

import java.io.PrintStream;
import java.security.Principal;
import java.security.PrivilegedAction;

import org.apache.log4j.Logger;

import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.UserPersistence;

/**
 * Govern the methods that each access control admin command has to support.
 * @author yeunga
 *
 */
public abstract class AbstractCommand implements PrivilegedAction<Object>
{
    private static final Logger log = Logger.getLogger(AbstractCommand.class);

    protected PrintStream systemOut = System.out;
    protected PrintStream systemErr = System.err;
	   
    /**
     * Set the system out.
     * @param printStream
     */
    public void setSystemOut(PrintStream printStream)
    {
        this.systemOut = printStream;
    }
    
    /**
     * Set the system err.
     * @param printStream
     */
    public void setSystemErr(PrintStream printStream)
    {
        this.systemErr = printStream;
    }

    @SuppressWarnings("unchecked")
    protected <T extends Principal> UserPersistence<T> getUserPersistence()
    {
        PluginFactory pluginFactory = new PluginFactory();
        return pluginFactory.getUserPersistence();
    }
}
