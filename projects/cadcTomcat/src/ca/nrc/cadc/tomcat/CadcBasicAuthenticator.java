package ca.nrc.cadc.auth;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;

public class CadcBasicAuthenticator extends RealmBase
{

    @Override
    protected String getName()
    {
        System.out.println("getName");
        return this.getClass().getSimpleName();
    }

    @Override
    protected String getPassword(final String username)
    {
        System.out.println("getPassword");
        return null;
    }

    @Override
    protected Principal getPrincipal(final String username)
    {
        System.out.println("getPrincipal");
        return null;
    }

    @Override
    public Principal authenticate(String username, String credentials)
    {
        System.out.println(String.format("username/credentials: %s/%s", username, credentials));
        System.out.println("Returning role public");
        List<String> roles = Arrays.asList("public");
        return new GenericPrincipal(username, credentials, roles);
//
//        return new Principal()
//        {
//            @Override
//            public String getName()
//            {
//                return "majorb";
//            }
//        };
    }

}
