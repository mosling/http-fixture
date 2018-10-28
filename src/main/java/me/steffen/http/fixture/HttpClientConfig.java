package me.steffen.http.fixture;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.Setter;
import me.steffen.http.common.Function;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.TreeMap;

/**
 * This class contains all used authorizations, connections and predefined addresses for an HttpClient.
 */
public class HttpClientConfig
{
    private static final Logger LOGGER = LogManager.getLogger( HttpClientConfig.class );

    //@formatter:off
    @Getter @Setter private Map<String, HttpAuth> auths = new TreeMap<>();

    @Getter @Setter private Map<String, HttpConnection> connections = new TreeMap<>();

    @Getter @Setter private Map<String, String> addresses = new TreeMap<>();
    //@formatter:on

    /**
     * @param configFile Resource or Filename
     * @param useFs      if true we can also load files from the filesystem
     * @return a new object, should be empty if no resource or files was found
     */
    public static HttpClientConfig createHttpClientObject( String configFile, boolean useFs )
    {
        HttpClientConfig cfg = new HttpClientConfig();

        try (InputStream configStream = Function.getInputStreamFromName( configFile, useFs ))
        {
            if ( null != configStream )
            {
                ObjectMapper mapper = new ObjectMapper();
                cfg = mapper.readValue( configStream, HttpClientConfig.class );
            }
        }
        catch ( IOException e )
        {
            LOGGER.error( "can't parse configuration file '{}' (allow file system access is {})", configFile, useFs );
            LOGGER.error( e );
        }

        return cfg;
    }

    public String toJson()
    {
        ObjectMapper om = new ObjectMapper();
        try
        {
            return om.writeValueAsString( this );
        }
        catch ( JsonProcessingException e )
        {
            LOGGER.error( e );
        }

        return "";
    }

    public void mergeConfiguration( HttpClientConfig c2 )
    {
        if ( null == c2 )
        {
            return;
        }

        c2
                .getAuths()
                .entrySet()
                .stream()
                .filter( e -> auths.containsKey( e.getKey() ) )
                .forEach( k -> LOGGER.warn( "overwrite exiting authorization key '{}'", k ) );

        c2
                .getConnections()
                .entrySet()
                .stream()
                .filter( c -> connections.containsKey( c.getKey() ) )
                .forEach( k -> LOGGER.warn( "overwrite exiting connection key '{}'", k ) );

        c2
                .getAddresses()
                .entrySet()
                .stream()
                .filter( a -> addresses.containsKey( a.getKey() ) )
                .forEach( k -> LOGGER.warn( "overwrite exiting address key '{}'", k ) );

        auths.putAll( c2.getAuths() );
        connections.putAll( c2.getConnections() );
        addresses.putAll( c2.getAddresses() );
    }

}
