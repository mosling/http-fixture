package me.steffen.http.security;

import org.apache.http.ssl.PrivateKeyDetails;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

/**
 * This class is used to find the right client alias for a given hostname. The strategy is the following:
 * <ul>
 * <li>"authz_rpc" is used as example and can be overwritten by constructor or set method</li>
 * <li>the keystore contains the alias "authz_rpc" as default key for non matching hosts </li>
 * <li>the keystore contains an alias "authz_rpc_&lt;host&gt;" for all hosts contains &lt;host&gt; in his name</li>
 * </ul>
 */
public class ClientPrivateKeyStrategy
        implements PrivateKeyStrategy
{
    private static final Logger LOGGER = LogManager.getLogger( ClientPrivateKeyStrategy.class );

    private final Map<String, String> hostAliasMap = new HashMap<>( 50 );

    private String aliasSeparator = "_";

    private String aliasBase;

    @Override
    public String chooseAlias( Map<String, PrivateKeyDetails> aliases, Socket socket )
    {
        // format for remote socket address <name>/<ip:port>
        String hostname = socket.getRemoteSocketAddress().toString();

        boolean hasAuthzRpc = false;

        if ( this.hostAliasMap.containsKey( hostname ) )
        {
            String a = hostAliasMap.get( hostname );
            LOGGER.debug( "client certificate: use cached alias {} for host {}", a, hostname );
            return a;
        }

        String aliasBaseSep    = aliasBase + aliasSeparator;
        int    aliasBaseSepLen = aliasBaseSep.length();

        for ( Entry<String, PrivateKeyDetails> entry : aliases.entrySet() )
        {
            String aliasName = entry.getKey();

            if ( aliasName.equals( aliasBase ) )
            {
                hasAuthzRpc = true;
                continue;
            }

            if ( aliasName.startsWith( aliasBaseSep ) )
            {
                String lastPart = aliasName.substring( aliasBaseSepLen );

                if ( lastPart.length() > 0 && hostname.contains( lastPart ) )
                {
                    this.hostAliasMap.put( hostname, aliasName );
                    LOGGER.debug( "client certificate: use host specific alias: {}", aliasName );
                    return aliasName;
                }
            }
        }

        if ( hasAuthzRpc )
        {
            LOGGER.debug( "client certificate: use general alias: {}", aliasBase );
            this.hostAliasMap.put( hostname, aliasBase );
            return aliasBase;
        }
        else
        {
            LOGGER.warn( "client certificate: no matching alias found for server {}.", hostname );
        }

        return "";
    }

    public String getAliasBase()
    {
        return aliasBase;
    }

    public ClientPrivateKeyStrategy setAliasBase( String aliasBase )
    {
        this.aliasBase = aliasBase;
        if ( null == this.aliasBase )
        {
            this.aliasBase = "";
        }
        return this;
    }

    public String getAliasSeparator()
    {
        return aliasSeparator;
    }

    public ClientPrivateKeyStrategy setAliasSeparator( String aliasSeparator )
    {
        this.aliasSeparator = aliasSeparator;
        return this;
    }
}
