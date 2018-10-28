package me.steffen.http.fixture;

import me.steffen.http.common.Function;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;

/**
 * Primarily exists this class, to create overcome the stupid HttpGet, HttpPost and so on classes used by HttpClient.
 */
public class HttpRequest
        extends HttpEntityEnclosingRequestBase
{
    private static final Logger LOGGER = LogManager.getLogger( HttpRequest.class );

    private String method;

    public HttpRequest addHeaderEntry( String name, String value )
    {
        super.addHeader( name, value );
        return this;
    }

    public HttpRequest addHeader( Map<String, String> header )
    {
        if ( null != header )
        {
            header.forEach( super::addHeader );
        }

        return this;
    }

    public HttpRequest setTextBody( String text )
    {
        try
        {
            StringEntity e = new StringEntity( text );
            setEntity( e );
        }
        catch ( UnsupportedEncodingException e )
        {
            LOGGER.error( "unsupported encoding for string: '{}', {}", text, e );
        }

        return this;
    }

    public void showHeaderInformation()
    {
        Function.logListElements( Level.DEBUG, "Header", new ArrayList<>( Arrays.asList( this.getAllHeaders() ) ) );
    }

    public void showTextInformation()
    {
        if ( null == getEntity() || !LOGGER.isDebugEnabled() )
        {
            return;
        }

        try
        {
            String tmpStr = EntityUtils.toString( getEntity() );
            if ( tmpStr != null && tmpStr.length() > 0 )
            {
                LOGGER.debug( "----------------- request data ------------------" );
                LOGGER.debug( tmpStr );
            }
            else
            {
                LOGGER.debug( "------------- EMPTY request data ----------------" );
            }
        }
        catch ( IOException e )
        {
            LOGGER.error( "ERROR: {}", e );
        }
    }

    public HttpRequest clear()
    {
        reset();
        setHeaders( null );
        setTextBody( "" );
        return this;
    }

    @Override
    public String getMethod()
    {
        return this.method;
    }

    public HttpRequest setMethod( String method )
    {
        this.method = method;
        return this;
    }
}
