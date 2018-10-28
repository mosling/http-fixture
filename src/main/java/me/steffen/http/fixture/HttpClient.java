package me.steffen.http.fixture;

import me.steffen.http.security.ClientPrivateKeyStrategy;
import me.steffen.http.security.JksManager;
import me.steffen.http.security.SecurityHelper;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.experimental.Accessors;
import org.apache.http.Header;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.MessageFormat;
import java.util.LinkedList;
import java.util.List;

@Accessors( fluent = true )
public class HttpClient
{
    private static final Logger LOGGER = LogManager.getLogger( HttpClient.class );

    private CloseableHttpClient client = null;

    @Getter private HttpClientConfig httpClientConfig;

    // read only to obtain the current manager from the http client, can be set during the build method
    @Getter private JksManager jksManager = null;

    // Create a http client which uses the LaxRedirect Strategy to redirect automatically all redirect responses
    public static HttpClient build( HttpClientArgs args, JksManager keyManager )
    {

        ObjectMapper om = new ObjectMapper();
        om.setVisibility( PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY );
        try
        {
            String argsHttp = om.writeValueAsString( args );
            LOGGER.debug( "creating HttpClient object from arguments: {}", argsHttp );
        }
        catch ( JsonProcessingException e )
        {
            LOGGER.error( e );
        }

        HttpClient hc = new HttpClient();

        // create a http client
        HttpClientBuilder clientBuilder = HttpClients.custom();

        if ( args.disableCookieHandling() )
        {
            clientBuilder.disableCookieManagement();
        }

        if ( keyManager != null )
        {
            hc.jksManager = keyManager;

            HostnameVerifier hv;
            switch ( args.hostnameVerifier() )
            {
                case "noop":
                    hv = new NoopHostnameVerifier();
                    break;
                case "logging":
                    hv = new NoopLoggingHostnameVerifier().jksManager( keyManager );
                    break;
                default:
                    hv = new DefaultHostnameVerifier();
                    break;
            }

            PrivateKeyStrategy pks = ( null == args.clientCertAlias() ) ?
                    null :
                    new ClientPrivateKeyStrategy().setAliasBase( args.clientCertAlias() );

            SSLContext sslcontext = args.trustAll() ?
                    SecurityHelper.getTrustAllSslContext( hc.jksManager, pks ) :
                    SecurityHelper.getSslContext( hc.jksManager, args.keystoreContainsCertificates(), pks );

            clientBuilder.setSSLSocketFactory( new SSLConnectionSocketFactory( sslcontext, hv ) );
        }

        RequestConfig requestConfig = RequestConfig
                .custom()
                .setConnectTimeout( args.requestTimeoutMs() )
                .setRedirectsEnabled( args.enableRedirect() )
                .build();

        hc.client = clientBuilder
                .setDefaultRequestConfig( requestConfig )
                .setRedirectStrategy( new LaxRedirectStrategy() )
                .setRetryHandler( new DefaultHttpRequestRetryHandler( 4, true ) )
                .build();

        hc.httpClientConfig = HttpClientConfig.createHttpClientObject( args.configFile(), true );

        return hc;
    }

    /**
     * @param name entry name
     * @param url  complete url
     */
    public void putHost( String name, String url )
    {
        httpClientConfig.getConnections().put( name, new HttpConnection( url ) );
    }

    /**
     * @param name   entry name
     * @param scheme used scheme (i.e. the protocol definition http, ftp, ...)
     * @param host   host name
     * @param port   port number, should be -1 if not used
     */
    public void putHost( String name, String scheme, String host, int port )
    {
        httpClientConfig.getConnections().put( name, new HttpConnection( scheme, host, port ) );
    }

    /**
     * @param name             entry name
     * @param authType         enumeration entry for authorization type (i.e. User, Client, Session, ...)
     * @param authName         authorization name
     * @param authPassword     authorization password
     * @param doBase64Encoding true if the entry must be base64 encoded before send
     */
    public void putAuth( String name, EnumAuthType authType, String authName, String authPassword,
            boolean doBase64Encoding )
    {
        httpClientConfig.getAuths().put( name, new HttpAuth( authType, authName, authPassword, doBase64Encoding ) );
    }

    /**
     * @param name    entry name
     * @param address address string
     */
    public void putAddress( String name, String address )
    {
        httpClientConfig.getAddresses().put( name, address );
    }

    /**
     * Create a path from the given list, the first entry is used as id for the registered path templates or as template
     * itself if no entry exists, all following entries are used during MessageFormat.format and should have the value
     * {n}.
     *
     * @param path list of String (first is template[id])
     * @return the created path
     */
    public String getPathString( List<String> path )
    {

        if ( null == path || path.isEmpty() )
        {
            return "";
        }

        String address = createAddressFromList( path );
        int    ll      = path.size();
        if ( ll > 1 )
        {
            Object[] arr = path.subList( 1, ll ).toArray();
            int      al  = arr.length;
            if ( address.contains( "'{'" ) || address.contains( "'}'" ) )
            {
                // set iteration to one, because format can handle quoted braces once only
                al = 1;
            }

            for ( int i = 0; i < al; ++i )
            {
                address = MessageFormat.format( address, arr );
            }
        }
        return address;
    }

    /**
     * Convert a list of strings into an address. The first entry is used as template and lookup value.
     * If the first entry is found into the httpClientConfig address mapping
     *
     * @param adrList list of strings
     * @return the address ready to use
     */
    private String createAddressFromList( List<String> adrList )
    {
        if ( null == adrList || adrList.isEmpty() )
        {
            return "";
        }

        String[] s       = adrList.get( 0 ).split( "\\?", 2 );
        String   address = httpClientConfig.getAddresses().get( s[0] );

        if ( address == null )
        {
            return adrList.get( 0 );
        }
        else
        {
            if ( s.length > 1 )
            {
                address = address + "?" + s[1];
            }

            LOGGER.debug( "Use registered mapping '{}' expands to '{}'.", s[0], address );
        }

        return address;
    }

    public void setAuthorizationHeader( HttpRequest request, String authorization )
    {
        if ( null == request || null == authorization || authorization.isEmpty() )
        {
            return;
        }

        HttpAuth x = httpClientConfig.getAuths().get( authorization );
        if ( null == x )
        {
            LOGGER.error( "HttpClient.execute.setAuthorizationHeader unknown auth identifier: {}", authorization );
        }
        else
        {
            EnumAuthType t = x.getAuthType();
            if ( t.isOverride() )
            {
                request.removeHeaders( t.getAuthHeaderField() );
                request.setHeader( t.getAuthHeaderField(), x.getHttpAuthorization() );
            }
            else
            {
                Header h = request.getFirstHeader( t.getAuthHeaderField() );
                if ( null != h )
                {
                    request.setHeader( t.getAuthHeaderField(),
                            ( h.getValue().isEmpty() ? "" : h.getValue() + ";" ) + x.getHttpAuthorization() );
                }
                else
                {
                    request.setHeader( t.getAuthHeaderField(), x.getHttpAuthorization() );
                }
            }
        }
    }

    public ResponseData execute( String host, String authorization, String path, HttpRequest request )
    {
        List<String> l = new LinkedList<>();
        l.add( path );
        return execute( host, authorization, l, request );
    }

    public ResponseData execute( String host, String authorization, List<String> addressAndArgs, HttpRequest request )
    {
        String        uriStr = this.getUriString( host, addressAndArgs );
        StringBuilder uriErr = new StringBuilder( "can't create URL string" );
        if ( null == host )
        {
            uriErr.append( ", host is null" );
        }
        if ( null == httpClientConfig.getConnections().get( host ) )
        {
            uriErr.append( ", missing host entry in connections" );
        }
        uriErr.append( " for host key '" );
        uriErr.append( host );
        uriErr.append( "'" );

        if ( null == uriStr || uriStr.isEmpty() )
        {
            LOGGER.error( "HttpClient.execute illegal argument: {}", uriErr );
            ResponseData rd = new ResponseData();
            rd.setLastError( "HttpClient.execute illegal argument: " + uriErr );
            rd.setResponse( null );
            return rd;
        }

        setAuthorizationHeader( request, authorization );
        return executeAddress( uriStr, request );
    }

    public ResponseData executeAddress( String uriStr, HttpRequest request )
    {
        if ( null == client )
        {
            throw new IllegalArgumentException( "client object; please initialize with a call to the build() method" );
        }
        if ( null == request )
        {
            throw new IllegalArgumentException( "request parameter can't be null" );
        }
        else if ( null == request.getMethod() || request.getMethod().isEmpty() )
        {
            throw new IllegalArgumentException( "method (GET,POST,...) is not set " );
        }

        ResponseData rd = new ResponseData();
        try
        {
            request.setURI( new URI( uriStr ) );

            if ( LOGGER.isDebugEnabled() )
            {
                String auth = "";
                Header ah   = request.getFirstHeader( "Authorization" );
                if ( null != ah )
                {
                    auth = "authorized with " + ah.getValue();
                }
                LOGGER.debug( "--------------- request information -------------" );
                InetAddress address = InetAddress.getByName( request.getURI().getHost() );
                LOGGER.debug( "{} [INET address: {}]", request.toString(), address.toString(), auth );
                request.showHeaderInformation();
                request.showTextInformation();
                LOGGER.debug( "-------------------------------------------------" );
            }

            long t = System.currentTimeMillis();
            rd.setResponse( this.client.execute( request ) );
            rd.setResponseTimeMillis( System.currentTimeMillis() - t );
        }
        catch ( URISyntaxException | IOException e )
        {
            LOGGER.error( "http execute exception {} thrown by {}", e.getClass().getName(), e.getMessage() );
            rd.setResponse( null );
            rd.setLastError( e.getMessage() );
        }

        return rd;
    }

    public String getConnectionUrl( String name )
    {
        HttpConnection x = httpClientConfig.getConnections().get( name );
        if ( null != x )
        {
            return x.getConnectionUrl();
        }

        return "";
    }

    public String getUriString( String host, List<String> path )
    {
        if ( null == host || !httpClientConfig.getConnections().containsKey( host ) )
        {
            return null;
        }

        HttpConnection hc = httpClientConfig.getConnections().get( host );
        if ( null == hc )

        {
            return null;
        }

        String hostUrl = hc.getConnectionUrl();
        String myPath  = path == null ? "" : getPathString( path );
        if ( myPath.length() > 0 )
        {
            if ( !myPath.startsWith( "/" ) )
            {
                hostUrl += "/";
            }
            hostUrl += myPath;
        }

        return hostUrl;

    }

}
