package me.steffen.http.fixture;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import me.steffen.http.security.JksManager;
import me.steffen.http.security.SecurityHelper;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

// same as NoopHostnameVerifier but shows some information
@Accessors( fluent = true )
public class NoopLoggingHostnameVerifier
        implements HostnameVerifier
{
    private static final Logger LOGGER = LogManager.getLogger( NoopLoggingHostnameVerifier.class );

    @Setter @Getter private JksManager jksManager;

    @Override
    public boolean verify( String s, SSLSession sslSession )
    {
        try
        {
            DefaultHostnameVerifier dhv = new DefaultHostnameVerifier();
            LOGGER.debug( "default verifier?: {}", dhv.verify( s, sslSession ) ? "<accepted>" : "<not accepted>" );

            LOGGER.debug( "ssl host         : {}", sslSession.getPeerHost() );
            LOGGER.debug( "ssl protocol     : {}", sslSession.getProtocol() );
            LOGGER.debug( "ssl cipher suite : {}", sslSession.getCipherSuite() );
            debugCertificateChain( sslSession.getPeerCertificateChain() );

            if ( sslSession.getLocalCertificates() != null )
            {
                Arrays
                        .asList( sslSession.getLocalCertificates() )
                        .forEach( c -> foundAliasAndShowInfo( "ssl[local]", (X509Certificate) c ) );
            }

        }
        catch ( SSLPeerUnverifiedException e )
        {
            LOGGER.error( e );
        }

        return true;
    }

    private boolean foundAliasAndShowInfo( String prefix, X509Certificate cert )
    {
        if ( null == cert )
        {
            return false;
        }

        String[] a = jksManager.getAliasName( cert );

        LOGGER.debug( "{}  ==  alias '{}'{}", prefix, a[0].isEmpty() ? "<not found>" : a[0],
                a[1].isEmpty() ? "" : "  ==  " + a[1] );

        SecurityHelper.traceCertificateInformation( cert, false );

        return !a[0].isEmpty();
    }

    public void debugCertificateChain( javax.security.cert.X509Certificate[] chain )
    {
        int cl = chain.length;
        for ( int i = 0; i < cl; ++i )
        {
            String          strChain = "ssl[" + i + ']';
            X509Certificate c        = SecurityHelper.convert( chain[i] );
            if ( null != c )
            {
                Optional<Boolean> ssc = SecurityHelper.isSelfSignedCertificate( c );
                LOGGER.debug( "{} self signed cert : {}", strChain, ssc.toString() );

                X509Certificate subject = jksManager.findPrincipalCertificate( c.getSubjectX500Principal() );
                X509Certificate issuer  = jksManager.findPrincipalCertificate( c.getIssuerX500Principal() );

                foundAliasAndShowInfo( strChain + " chain certificate ", c );
                foundAliasAndShowInfo( strChain + " subject principal ", subject );
                foundAliasAndShowInfo( strChain + " issuer principal  ", issuer );
            }
        }
    }

}
