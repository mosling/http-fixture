package me.steffen.http.security;

import me.steffen.http.common.Function;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

public class SecurityHelper
{
    private static final Logger LOGGER = LogManager.getLogger( SecurityHelper.class );

    private SecurityHelper()
    {
        // functional class
    }

    public static X509Certificate createX509Certificate( String certString )
    {
        try
        {
            String cleanStr = certString.replaceAll( "\n", "" );
            cleanStr = cleanStr.replace( "-----BEGIN CERTIFICATE-----", "" );
            cleanStr = cleanStr.replace( "-----END CERTIFICATE-----", "" );
            byte[]               ba = Base64.getDecoder().decode( cleanStr );
            ByteArrayInputStream bs = new ByteArrayInputStream( ba );

            return (X509Certificate) CertificateFactory.getInstance( "X.509" ).generateCertificate( bs );
        }
        catch ( CertificateException e )
        {
            LOGGER.error( e );
        }

        return null;
    }

    public static PrivateKey createPrivateKey( String pkcs8 )
    {
        try
        {
            String cleanStr = pkcs8.replaceAll( "\n", "" );
            cleanStr = cleanStr.replace( "-----BEGIN PRIVATE KEY-----", "" );
            cleanStr = cleanStr.replace( "-----END PRIVATE KEY-----", "" );

            byte[]              keyBytes = Base64.getDecoder().decode( cleanStr );
            KeyFactory          kf       = KeyFactory.getInstance( "RSA" );
            PKCS8EncodedKeySpec spec     = new PKCS8EncodedKeySpec( keyBytes );

            return kf.generatePrivate( spec );
        }
        catch ( NoSuchAlgorithmException | InvalidKeySpecException e )
        {
            LOGGER.error( e );
        }

        return null;
    }

    public static SSLContext getTrustAllSslContext( JksManager jksManager, PrivateKeyStrategy privateKeyStrategy )
    {
        SSLContextBuilder sslContextBuilder = SSLContexts.custom();
        SSLContext        sslContext        = null;

        try
        {
            KeyStore keyMaterial = jksManager.keystore();
            if ( null != keyMaterial )
            {
                sslContextBuilder.loadKeyMaterial( keyMaterial, jksManager.args().keystoreKeySecret().toCharArray(),
                        privateKeyStrategy );
            }

            sslContextBuilder.loadTrustMaterial( null, ( X509Certificate[] chain, String authType ) -> true );

            LOGGER.error( "Using the trust all hosts mode should be used during development only." );
            sslContext = sslContextBuilder.build();

        }
        catch ( NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | KeyManagementException e )
        {
            LOGGER.error( "getTrustAllSslContext: {}", e );
        }

        return sslContext;
    }

    /**
     * configure SSL context use keystore as trusted material source if keystoreContainsTrustMaterial flag is true in
     * this case a existing truststore is ignored
     *
     * @param jksManager                    the Java Keystore Manager(JKS) containing the used key- and truststore
     * @param keyStoreContainsTrustMaterial SSL context uses the information from the keystore as trust material
     * @param privateKeyStrategy            used for finding alias for client side identification
     * @return SSLContent the created SSLContent object
     */
    public static SSLContext getSslContext( JksManager jksManager, boolean keyStoreContainsTrustMaterial,
            PrivateKeyStrategy privateKeyStrategy )
    {
        SSLContext sslContext = null;
        boolean    trust      = false;
        try
        {
            KeyStore keyMaterial   = jksManager.keystore();
            KeyStore trustMaterial = jksManager.truststore();

            SSLContextBuilder sslContextBuilder = SSLContexts.custom();

            if ( null != keyMaterial )
            {
                sslContextBuilder.loadKeyMaterial( keyMaterial, jksManager.args().keystoreKeySecret().toCharArray(),
                        privateKeyStrategy );
            }

            if ( keyStoreContainsTrustMaterial )
            {
                sslContextBuilder.loadTrustMaterial( keyMaterial, null );
                trust = true;
            }
            else if ( null != trustMaterial )
            {
                sslContextBuilder.loadTrustMaterial( trustMaterial, null );
                trust = true;
            }

            if ( !trust )
            {
                LOGGER.error( "SSL Context: no truststore loaded." );
            }

            sslContext = sslContextBuilder.build();
        }
        catch ( NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | KeyManagementException e )
        {
            LOGGER.error( "getSslContext: {}", e );
        }

        return sslContext;
    }

    public static String getX509PemString( Certificate cert )
    {
        Base64.Encoder encoder   = Base64.getEncoder();
        String         certBegin = "-----BEGIN CERTIFICATE-----\n";
        String         certEnd   = "-----END CERTIFICATE-----";

        try
        {
            byte[] derCert    = cert.getEncoded();
            String pemCertPre = new String( encoder.encode( derCert ), StandardCharsets.UTF_8 );
            return certBegin + pemCertPre + certEnd;
        }
        catch ( CertificateEncodingException e )
        {
            LOGGER.error( e );
        }

        return null;
    }

    // Converts to java.security (the current default)
    public static X509Certificate convert( javax.security.cert.X509Certificate cert )
    {
        try
        {
            byte[]               encoded = cert.getEncoded();
            ByteArrayInputStream bis     = new ByteArrayInputStream( encoded );
            CertificateFactory   cf      = CertificateFactory.getInstance( "X.509" );
            return (X509Certificate) cf.generateCertificate( bis );
        }
        catch ( javax.security.cert.CertificateEncodingException | CertificateException e )
        {
            LOGGER.error( e );
        }
        return null;
    }

    // Converts to javax.security
    @SuppressWarnings( "UnnecessaryFullyQualifiedName" )
    public static javax.security.cert.X509Certificate convert( X509Certificate cert )
    {
        try
        {
            byte[] encoded = cert.getEncoded();
            return javax.security.cert.X509Certificate.getInstance( encoded );
        }
        catch ( CertificateEncodingException | javax.security.cert.CertificateException e )
        {
            LOGGER.error( e );
        }
        return null;
    }

    public static Optional<Boolean> isSelfSignedCertificate( Certificate cert )
    {
        try
        {
            // Try to verify certificate signature with its own public key
            PublicKey key = cert.getPublicKey();
            cert.verify( key );
            return Optional.of( true );
        }
        catch ( SignatureException | InvalidKeyException sigEx )
        {
            // Invalid signature --> not self-signed
            // Invalid key --> not self-signed
            return Optional.of( false );
        }
        catch ( CertificateException | NoSuchAlgorithmException | NoSuchProviderException ex )
        {
            LOGGER.warn( ex.getMessage() );
            LOGGER.debug( ex );
            return Optional.empty();
        }
    }

    public static String getThumbPrint( X509Certificate cert, String algorithm )
    {
        try
        {
            MessageDigest md  = MessageDigest.getInstance( algorithm );
            byte[]        der = cert.getEncoded();
            md.update( der );
            byte[] digest = md.digest();
            return Function.hexify( digest );
        }
        catch ( NoSuchAlgorithmException | CertificateEncodingException e )
        {
            LOGGER.error( e );
        }

        return "<not possible>";
    }

    public static String[] getAlternativeNames( Collection<List<?>> c )
    {
        if ( c != null )
        {
            List<String> altList = new LinkedList<>();
            for ( List<?> list : c )
            {
                int type = ( (Number) list.get( 0 ) ).intValue();
                // If type is 2, then we've got a dNSName
                if ( type == 2 )
                {
                    String s = (String) list.get( 1 );
                    altList.add( s );
                }
            }

            if ( !altList.isEmpty() )
            {
                String[] altStr = new String[altList.size()];
                altList.toArray( altStr );
                return altStr;
            }
        }
        return new String[0];
    }

    public static String[] getIssuerAlts( X509Certificate cert )
    {
        try
        {
            return getAlternativeNames( cert.getIssuerAlternativeNames() );
        }
        catch ( CertificateParsingException e )
        {
            LOGGER.error( e );
        }

        return new String[0];
    }

    public static String[] getSubjectAlts( X509Certificate cert )
    {
        try
        {
            return getAlternativeNames( cert.getSubjectAlternativeNames() );
        }
        catch ( CertificateParsingException e )
        {
            LOGGER.error( e );
        }

        return new String[0];
    }

    public static void traceCertificateInformation( Certificate cert, boolean showCert )
    {
        if ( LOGGER.isTraceEnabled() )
        {
            List<String> l = certificateInformation( cert, showCert );
            l.forEach( LOGGER::trace );
        }
    }

    public static List<String> certificateInformation( Certificate cert, boolean showCert )
    {
        List<String> cl = new ArrayList<>();

        if ( null == cert )
        {
            cl.add( "certificate is null" );
            return cl;
        }

        if ( cert instanceof X509Certificate )
        {
            X509Certificate x509 = (X509Certificate) cert;
            if ( showCert )
            {
                cl.add( String.format( " %s ", cert.toString() ) );
            }

            cl.add( String.format( "  version          : V%s ", x509.getVersion() ) );
            cl.add( String.format( "  serial           : %s ", x509.getSerialNumber() ) );
            cl.add( String.format( "  issuer           : %s ", x509.getIssuerX500Principal().getName() ) );
            String[] ai = getIssuerAlts( x509 );

            for ( String s : ai )
            {
                cl.add( String.format( "      alternative  : %s ", s ) );
            }

            cl.add( String.format( "  valid from .. to : %s .. %s ", Function.getUtcString( x509.getNotBefore() ),
                    Function.getUtcString( x509.getNotAfter() ) ) );
            cl.add( String.format( "  subject          : %s ", x509.getSubjectX500Principal().getName() ) );
            String[] an = getSubjectAlts( x509 );

            for ( String s : an )
            {
                cl.add( String.format( "      alternative  : %s ", s ) );
            }

            cl.add( String.format( "  algorithm        : %s / OID: %s ", x509.getSigAlgName(), x509.getSigAlgOID() ) );
            cl.add( String.format( "  public key class : %s ", x509.getPublicKey().getClass().toString() ) );
            if ( x509.getPublicKey() instanceof RSAKey )
            {
                cl.add( String.format( "  RSA key length   : %s ",
                        ( (RSAKey) x509.getPublicKey() ).getModulus().bitLength() ) );
            }
            else if ( x509.getPublicKey() instanceof ECPublicKey )
            {
                cl.add( String.format( "  EC params        : %s ",
                        ( (ECPublicKey) x509.getPublicKey() ).getParams().toString() ) );
            }
            cl.add( String.format( "  self-signed      : %s ", isSelfSignedCertificate( x509 ).toString() ) );
            cl.add( String.format( "  SHA-1            : %s ", getThumbPrint( x509, "SHA-1" ) ) );
        }
        else
        {
            cl.add( String.format( "  cert info : %s", cert.toString() ) );
        }

        return cl;
    }
}
