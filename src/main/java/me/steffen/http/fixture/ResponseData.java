package me.steffen.http.fixture;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.Getter;
import lombok.Setter;
import me.steffen.http.common.Function;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.HttpCookie;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class ResponseData
{
    private static final Logger LOGGER = LogManager.getLogger( ResponseData.class );

    @Getter @Setter private long responseTimeMillis;

    @Getter private CloseableHttpResponse response;

    @Getter private final List<HttpCookie> responseCookies = new LinkedList<>();

    @Getter private String responseContent = "";

    @Getter private int status;

    @Getter @Setter private String lastError = "";

    @Getter private String contenttype;

    public static String cookieToString( HttpCookie c )
    {
        return MessageFormat.format( "{0}{1}{2}{3}{4}", c.getValue(), optionalValue( "; path=", c.getPath() ),
                optionalValue( "; domain=", c.getDomain() ), c.isHttpOnly() ? " httpOnly" : "",
                c.hasExpired() ? " expired" : "" );
    }

    public static String optionalValue( String prefix, String v )
    {
        return v == null || v.isEmpty() ? "" : prefix + v;
    }

    public static String indexedName( Map<String, Integer> m, String s )
    {
        if ( m.containsKey( s ) )
        {
            Integer i = m.get( s );
            i++;
            m.put( s, i );
            return s + "[" + i + "]";
        }
        else
        {
            m.put( s, 0 );
        }

        return s;
    }

    // create an JSON structure representing the response information
    public String toJson( boolean withHeader, boolean withData )
    {
        ObjectMapper om = new ObjectMapper();

        ObjectNode respObj = om.createObjectNode();
        ObjectNode info    = respObj.putObject( "response" );
        info.put( "status", status );
        info.put( "descr", HttpStatusCode.explain( status ) );
        info.put( "content-type", contenttype );
        info.put( "time_ms", responseTimeMillis );
        if ( withHeader )
        {
            ObjectNode cl = respObj.putObject( "cookies" );
            ObjectNode hl = respObj.putObject( "headers" );
            Arrays.stream( response.getAllHeaders() ).forEach( h -> hl.put( h.getName(), h.toString() ) );
            responseCookies.forEach( c -> cl.put( c.getName(), cookieToString( c ) ) );
        }
        if ( withData )
        {
            respObj.put( "content", responseContent );
        }

        try
        {
            return om.writerWithDefaultPrettyPrinter().writeValueAsString( respObj );
        }
        catch ( JsonProcessingException e )
        {
            LOGGER.error( e );
            return "Error writing json " + e.getMessage();
        }
    }

    public void showResponse( boolean withHeader, Level ll )
    {
        if ( null == this.response || !LOGGER.isEnabled( ll ) )
        {
            return;
        }
        LOGGER.log( ll, "-------------- response information -------------" );
        LOGGER.log( ll, "Status            : {} {}", status, HttpStatusCode.explain( status ) );
        LOGGER.log( ll, "Content-Type      : {}", contenttype );
        LOGGER.log( ll, "Response-Time(ms) : {}", responseTimeMillis );

        if ( withHeader )
        {
            Function.logListElements( ll, "Header",
                    Arrays.stream( response.getAllHeaders() ).collect( Collectors.toList() ) );

            Function.logListElements( ll, "Cookie",
                    responseCookies.stream().map( ResponseData::cookieToString ).collect( Collectors.toList() ) );
        }

        LOGGER.log( ll, "----------------- response data -----------------\n{}\n", responseContent );
        LOGGER.log( ll, "-------------------------------------------------" );
    }

    public String getHeader( String headerName )
    {
        List<Header> hl = Arrays.asList( response.getHeaders( headerName ) );

        if ( hl.size() > 1 )
        {
            LOGGER.warn( "multiple entries for the same header name '{}'", headerName );
            AtomicInteger i = new AtomicInteger( 0 );
            hl.forEach( h -> LOGGER.warn( "   {} {}", i.getAndIncrement() == 0 ? "*" : "-", h.toString() ) );
        }

        return hl.isEmpty() ? "" : hl.get( 0 ).getValue();
    }

    public List<HttpCookie> findCookie( String cookieName )
    {
        return responseCookies
                .stream()
                .filter( c -> cookieName.equalsIgnoreCase( c.getName() ) )
                .collect( Collectors.toList() );
    }

    public String getCookie( String cookieName )
    {
        List<HttpCookie> cl = findCookie( cookieName );

        if ( cl.size() > 1 )
        {
            LOGGER.warn( "multiple entries for the same cookie name '{}'", cookieName );
            AtomicInteger i = new AtomicInteger( 0 );
            cl.forEach( c -> LOGGER.warn( "   {} {}", i.getAndIncrement() == 0 ? "*" : "-", cookieToString( c ) ) );
        }
        return cl.isEmpty() ? "" : cl.get( 0 ).getValue();
    }

    public void setResponse( CloseableHttpResponse response )
    {
        this.response = response;
        responseContent = "";
        responseCookies.clear();

        if ( null != response )
        {
            HttpEntity entity = response.getEntity();
            if ( null != entity )
            {
                try
                {
                    this.responseContent = EntityUtils.toString( entity );
                }
                catch ( IOException e )
                {
                    LOGGER.error( e );
                    this.responseContent = "";
                }
            }

            // ignoring additional cookie options like secure,path,domain,expires,...
            for ( Header he : response.getHeaders( "Set-Cookie" ) )
            {
                responseCookies.addAll( HttpCookie.parse( he.getValue() ) );
            }

            StatusLine responseStatus = response.getStatusLine();

            status = null != responseStatus ? responseStatus.getStatusCode() : -1;

            contenttype = getHeader( "Content-Type" );
        }
    }
}
