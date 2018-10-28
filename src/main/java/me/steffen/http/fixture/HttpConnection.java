package me.steffen.http.fixture;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;
import org.apache.http.HttpHost;
import org.apache.http.client.utils.URIUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.net.URISyntaxException;

public class HttpConnection
{
    private static final Logger LOGGER = LogManager.getLogger( HttpConnection.class );

    // @formatter:off
    @Getter @Setter private String protocol;

    @Getter @Setter private String url;

    @Getter @Setter private int port = -1;
    // @formatter:on

    public HttpConnection()
    {
        // Jackson need the default constructor
    }

    public HttpConnection( String protocol, String url, int port )
    {
        this.protocol = protocol;
        this.url = url;
        this.port = port;
    }

    public HttpConnection( String hostUrl )
    {
        try
        {
            HttpHost hc = URIUtils.extractHost( new URI( hostUrl ) );
            if ( hc != null )
            {
                protocol = hc.getSchemeName();
                url = hc.getHostName();
                port = hc.getPort();
            }
            else
            {
                LOGGER.error( "can't extract host information from url '{}'", url );
            }
        }
        catch ( URISyntaxException e )
        {
            LOGGER.error( "addHost URI {}", e );
        }
    }

    @Override
    public String toString()
    {
        return getConnectionUrl();
    }

    @JsonIgnore
    public String getConnectionUrl()
    {
        String x = url;
        if ( !protocol.isEmpty() )
        {
            x = protocol + "://" + x;
        }
        if ( port > 0 )
        {
            x = x + ":" + Integer.toString( port );
        }

        return x;
    }
}
