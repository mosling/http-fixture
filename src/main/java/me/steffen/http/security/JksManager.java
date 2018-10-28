package me.steffen.http.security;

import me.steffen.http.common.Function;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

@Accessors( fluent = true )
public class JksManager
{
    private static final Logger LOGGER = LogManager.getLogger( JksManager.class );

    // @formatter:off
    @Getter @Setter private String jdkStoreName        = System.getProperty( "java.home" ) + "/lib/security/cacerts";
    @Getter @Setter private String jdkAliasPostfix     = "-jdk";
    @Setter @Getter private boolean lookIntoFilesystem = false;

    // keystore objects
    @Getter private KeyStore keystore;
    @Getter private KeyStore truststore;
    @Getter private final JksManagerArgs args;
    // @formatter:on

    private final List<String> jdkImportedAliasList = new LinkedList<>();

    public JksManager( JksManagerArgs args )
    {
        this.args = args;
        ObjectMapper om = new ObjectMapper();
        om.setVisibility( PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY );

        build();

        try
        {
            String argsJson = om.writeValueAsString( args );
            LOGGER.debug( "creating JksManager object from arguments: {}", argsJson );
        }
        catch ( JsonProcessingException e )
        {
            LOGGER.error( e );
        }
    }

    /**
     * This method get the instance from the suggested keystore type to initialize the used
     * keystore or truststore. First we read the header from a given file or resource
     * and detect JKS or JCEKS keystore type.
     *
     * @param isKeystore if true we initialize keystore else truststore
     */
    private void initializeStoreType( boolean isKeystore )
    {
        String tp = KeyStore.getDefaultType();
        String ct = isKeystore ? args.keystoreType() : args.trustStoreType();
        String sn = isKeystore ? args.keystore() : args.truststore();

        String jks = "fe:ed:fe:ed";
        String jce = "ce:ce:ce:ce";

        if ( !sn.isEmpty() )
        {
            byte[] magic = Function.getHeaderFromName( sn, args.allowFilesystemLookup(), 4 );
            if ( magic.length == 4 )
            {
                String mStr = Function.hexify( magic );
                if ( jks.equalsIgnoreCase( mStr ) )
                {
                    tp = "JKS";
                }
                else if ( jce.equalsIgnoreCase( mStr ) )
                {
                    tp = "JCEKS";
                }
                else
                {
                    LOGGER.error( "unknown keystore header '{}' found for '{}' (current available JKS={}; JCEKS={})",
                            mStr, sn, jks, jce );
                }
            }
        }

        try
        {
            if ( isKeystore )
            {
                if ( !ct.isEmpty() && !ct.equalsIgnoreCase( tp ) )
                {
                    LOGGER.warn( "determined KeyStore type '{}' differs from store type argument '{}'", tp, ct );
                }
                args.keystoreType( ct.isEmpty() ? tp : ct );
                keystore = KeyStore.getInstance( args.keystoreType() );
            }
            else
            {
                if ( !ct.isEmpty() && !ct.equalsIgnoreCase( tp ) )
                {
                    LOGGER.warn( "determined TrustStore type '{}' differs from store type argument '{}'", tp, ct );
                }
                args.trustStoreType( ct.isEmpty() ? tp : ct );
                truststore = KeyStore.getInstance( args.trustStoreType() );
            }
        }
        catch ( KeyStoreException e )
        {
            LOGGER.error( e );
        }
    }

    private void build()
    {

        boolean validKeystore   = false;
        boolean validTruststore = false;

        // loading keystore
        try (InputStream keystoreInput = Function.getInputStreamFromName( args.keystore(), lookIntoFilesystem ))
        {
            if ( null != keystoreInput )
            {
                initializeStoreType( true );
                keystore.load( keystoreInput, args.keystoreSecret().toCharArray() );
                validKeystore = true;
            }
        }
        catch ( CertificateException | NoSuchAlgorithmException | IOException e )
        {
            LOGGER.error( "setKeystore: {}", e );
        }

        // loading trusted certificates from the truststore
        try (InputStream truststoreInput = Function.getInputStreamFromName( args.truststore(), lookIntoFilesystem ))
        {
            if ( null != truststoreInput )
            {
                initializeStoreType( false );
                truststore.load( truststoreInput, args.truststoreSecret().toCharArray() );
                validTruststore = true;
            }

        }
        catch ( CertificateException | NoSuchAlgorithmException | IOException e )
        {
            LOGGER.error( "setTruststore: {}", e );
        }

        // initialize non loaded keystore empty (needs to call the load method)
        // and add optional JDK certificates
        try
        {
            if ( !validKeystore )
            {
                initializeStoreType( true );
                keystore.load( null, null == args.keystoreSecret() ? null : args.keystoreSecret().toCharArray() );
            }

            if ( !validTruststore )
            {
                initializeStoreType( false );
                truststore.load( null, null == args.truststoreSecret() ? null : args.truststoreSecret().toCharArray() );
            }

            // adding JDK certificate to the truststore
            if ( args.includeJdkCertificate() )
            {
                addJdkCertificatesToTruststore( jdkAliasPostfix );
            }
        }
        catch ( CertificateException | NoSuchAlgorithmException | IOException e )
        {
            LOGGER.error( "initialize empty store failed : {}", e );
        }
    }

    private String getAliasList( KeyStore store, String listEntrySeparator )
    {
        String aliasList = "";
        if ( null != store )
        {
            try
            {
                aliasList = Collections
                        .list( store.aliases() )
                        .stream()
                        .filter( s -> !s.endsWith( jdkAliasPostfix ) )
                        .collect( Collectors.joining( listEntrySeparator ) );
            }
            catch ( KeyStoreException e )
            {
                LOGGER.error( e );
            }
        }

        return aliasList;
    }

    /**
     * The getCertificate checks that the byte array from getEncodedInternal() is equal.
     *
     * @param cert the certificate
     * @return [1] alias name or empty string (not null), [2] truststore or keystore
     */
    public String[] getAliasName( Certificate cert )
    {
        String[] l = new String[2];
        try
        {
            l[0] = truststore.getCertificateAlias( cert );
            l[1] = "truststore";

            if ( null == l[0] )
            {
                l[0] = keystore.getCertificateAlias( cert );
                l[1] = "keystore";
            }

        }
        catch ( KeyStoreException e )
        {
            LOGGER.error( e );
        }
        finally
        {
            if ( l[0] == null )
            {
                l[0] = "";
                l[1] = "";
            }
        }

        return l;
    }

    /**
     * This method find the first (are there more possible?) certificate in the truststore
     * which has the same X500Principal issuer as the requested certificate.
     * Why? This is used to verify if we trust a server connection. Often the certificate we trust
     * are not included in the certificate chain come from the server. But a minimum of this certificates
     * must have an issuer that we trust.
     *
     * @param principal the principal issuer we're looking for
     * @return the X509 certificate or null if not found
     */
    public X509Certificate findPrincipalCertificate( X500Principal principal )
    {
        if ( null == principal )
        {
            return null;
        }

        try
        {
            List<String> l = Collections.list( truststore.aliases() );
            for ( String a : l )
            {
                if ( ( (X509Certificate) truststore.getCertificate( a ) ).getIssuerX500Principal().equals( principal ) )
                {
                    return (X509Certificate) truststore.getCertificate( a );
                }
            }
        }
        catch ( KeyStoreException e )
        {
            LOGGER.error( e );
        }

        return null;
    }

    public void importKeystoreEntry( String ks, String storePwd, String key, String newAlias, boolean isBase64Encoded )
    {
        try
        {
            InputStream stream;
            if ( isBase64Encoded )
            {
                stream = new ByteArrayInputStream( Base64.getDecoder().decode( ks.replaceAll( "\n", "" ) ) );
            }
            else
            {
                stream = new ByteArrayInputStream( ks.getBytes( StandardCharsets.UTF_8 ) );
            }

            KeyStore tempKeystore = KeyStore.getInstance( KeyStore.getDefaultType() );
            tempKeystore.load( stream, storePwd.toCharArray() );
            LOGGER.info( "temporary imported aliases: {}", getAliasList( tempKeystore, ";" ) );

            KeyStore.PasswordProtection sp = new KeyStore.PasswordProtection( storePwd.toCharArray() );
            KeyStore.PasswordProtection kp = new KeyStore.PasswordProtection( args.keystoreKeySecret().toCharArray() );

            KeyStore.Entry e = tempKeystore.getEntry( key, sp );
            if ( null != e )
            {
                keystore.setEntry( newAlias, e, kp );
            }
            else
            {
                LOGGER.warn( "Can't read entry '{}' from the keystore --> ignored.", key );
            }

        }
        catch ( UnrecoverableEntryException | KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e )
        {
            LOGGER.error( "importKeystoreEntry: {}", e );
        }
    }

    /**
     * The new create key entry becomes the same key password as the other key in this keystore from the variable.
     *
     * @param alias       the alias for the new created entry
     * @param key         the private key as string (must be exported as not encrypted)
     * @param certificate the certificate for the key
     */
    public void putPrivateKeyFromString( String alias, String key, String certificate )
    {
        try
        {
            PrivateKey k = SecurityHelper.createPrivateKey( key );
            if ( null != k )
            {
                X509Certificate[] chain = new X509Certificate[1];
                chain[0] = SecurityHelper.createX509Certificate( certificate );
                KeyStore.PasswordProtection keyPwd = new KeyStore.PasswordProtection(
                        args.keystoreKeySecret().toCharArray() );

                keystore.setEntry( alias, new KeyStore.PrivateKeyEntry( k, chain ), keyPwd );
            }
            else
            {
                LOGGER.error( "Can't create a private key from the data" );
            }
        }
        catch ( KeyStoreException e )
        {
            LOGGER.error( e );
        }

    }

    private void addJdkCertificatesToTruststore( String postfix )
    {
        try (FileInputStream is = new FileInputStream( jdkStoreName ))
        {
            KeyStore jdkKeyStore = KeyStore.getInstance( KeyStore.getDefaultType() );
            jdkKeyStore.load( is, "changeit".toCharArray() );

            jdkImportedAliasList.clear();
            List<String> al = Collections.list( jdkKeyStore.aliases() );
            for ( String a : al )
            {
                if ( jdkKeyStore.isCertificateEntry( a ) )
                {
                    truststore.setCertificateEntry( a + postfix, jdkKeyStore.getCertificate( a ) );
                    jdkImportedAliasList.add( a );
                }
                else
                {
                    LOGGER.info( "ignore entry : {}", a );
                }
            }
        }
        catch ( KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e )
        {
            // ignore error loading jdk truststore
            LOGGER.warn( e );
            LOGGER.warn( "can't load JDK keystore from {}", jdkStoreName );
        }
    }

    /**
     * @param keyAlias the alias for the entry in the keystore, that's the only store, because later we need the private
     *                 key to sign data
     * @return algorithm name (java.security.cert.X509Certificate) as string
     */
    public String getSignatureAlgorithmName( String keyAlias )
    {
        String signatureAlgName = "";

        try
        {
            if ( null != keystore )
            {
                X509Certificate cert = (X509Certificate) keystore.getCertificate( keyAlias );
                if ( null != cert )
                {
                    signatureAlgName = cert.getSigAlgName();
                }
            }
        }
        catch ( KeyStoreException ex )
        {
            LOGGER.error( "getSignatureAlgorithmName: {}", ex );
        }

        return signatureAlgName;
    }

    /**
     * @param keyAlias         alias of the stored key-pair
     * @param keyAliasPassword optional password for the key pair, if null the keystore password is used
     * @return null or the PrivateKey object
     */
    public PrivateKey getPrivateKey( String keyAlias, String keyAliasPassword )
    {
        PrivateKey privateKey;

        try
        {
            privateKey = (PrivateKey) keystore.getKey( keyAlias, null == keyAliasPassword ?
                    args.keystoreKeySecret().toCharArray() :
                    keyAliasPassword.toCharArray() );
        }
        catch ( KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e )
        {
            LOGGER.error( "getPrivateKey: {}", e );
            privateKey = null;
        }

        if ( privateKey == null )
        {
            LOGGER.error( "Failed to retrieve private key from {}.", args.keystore() );
        }

        return privateKey;
    }

    public PublicKey getPublicKey( String keyAlias )
    {
        X509Certificate cert = getCertificate( keyAlias );
        if ( cert != null )
        {
            return cert.getPublicKey();
        }

        return null;
    }

    public X509Certificate getCertificate( String certAlias )
    {
        X509Certificate certificate = null;

        try
        {
            if ( keystore.containsAlias( certAlias ) )
            {
                certificate = (X509Certificate) keystore.getCertificate( certAlias );
            }
            else if ( truststore.containsAlias( certAlias ) )
            {
                certificate = (X509Certificate) truststore.getCertificate( certAlias );
            }
        }
        catch ( Exception e )
        {
            LOGGER.error( "getCertificate: {}", e );
        }

        return certificate;
    }

    public JksManager debugMode( boolean activate )
    {
        if ( activate )
        {
            System.setProperty( "javax.net.debug", "all" );
        }
        return this;
    }

    @Override
    public String toString()
    {
        String listSep         = "\",\"";
        String sourceProperty  = "\"sourceName\":";
        String aliasesProperty = "\"aliases\":";

        String info = "{\"jksManager\":{";

        info += "\"keystore\": {";
        info += "\"sourceName\": \"" + args.keystore() + "\",";
        info += "\"aliases\":[\"" + getAliasList( keystore, listSep ) + "\"]},";

        info += "\"truststore\": {";
        info += sourceProperty + '"' + args.truststore() + "\",";
        info += aliasesProperty + "[\"" + getAliasList( truststore, listSep ) + "\"]},";

        if ( args.includeJdkCertificate() )
        {
            info += "\"jdkstore\": {";
            info += sourceProperty + '"' + jdkStoreName + "\",";
            info += aliasesProperty + "[\"" + jdkImportedAliasList.stream().collect( Collectors.joining( listSep ) )
                    + "\"],";
            info += "\"jdkAliasPostfix\": \"" + jdkAliasPostfix + "\"},";
        }

        info += "\"filesystemAccess\": " + lookIntoFilesystem;
        info += "} }";

        return info;
    }
}
