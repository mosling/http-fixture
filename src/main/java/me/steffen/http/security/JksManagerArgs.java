package me.steffen.http.security;

import me.steffen.http.common.Function;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/**
 * This class contains the arguments to build a JksManager object. Every Java Keystore (Jks) has an password and the
 * entries in the keystore can have different passwords.
 * <b>Attention</b>: If the keys in the keystore are used as client
 * certificates in the SSL context {@link SecurityHelper#getSslContext(JksManager, boolean, PrivateKeyStrategy)}
 * than every key in the keystore file must have the same password, this can be different from the keystore password.
 * <ul>
 * <li>truststore: a filesystem or a resource location depending at the allowFileSystemLookup setting</li>
 * <li>keystore:  a filesystem or a resource location depending at the allowFileSystemLookup setting</li>
 * <li>truststoreSecret: the password to access the truststore</li>
 * <li>keystoreSecret: the password to access the keystore</li>
 * <li>keystoreKeySecret: the password to access the keystore secrets, this must be the same for all keystores
 * entries if this entries are used as client certificates</li>
 * <li>includeJdkCertificate: includes the existing JRE certificates into the truststore values. To prevent
 * naming conflicts in this case all JRE certificates becomes the postfix *-jdk*</li>
 * <li>allowFileSystemLookup: Is this true the java keystore files are first checked if the exists in the
 * filesystem, if not found the class looks into the resources.</li>
 * <li>debugMode: is this true we set the property `javax.net.debug` to <b>all</b>.</li>
 * </ul>
 */
@Accessors( fluent = true )
public class JksManagerArgs
{
    private static final Logger LOGGER = LogManager.getLogger( JksManagerArgs.class );

    // @formatter:off
    @Setter @Getter @JsonProperty( "truststoreType")                          private String trustStoreType         = "";
    @Setter @Getter @JsonProperty( "truststore" )                             private String  truststore            = "";
    @Setter @Getter @JsonProperty( value = "truststoreSecret",
                                   access = JsonProperty.Access.WRITE_ONLY )  private String  truststoreSecret      = "";


    @Setter @Getter @JsonProperty( "keystoreType")                            private String keystoreType           = "";
    @Setter @Getter @JsonProperty( "keystore" )                               private String  keystore              = "";
    @Setter @Getter @JsonProperty( value = "keystoreSecret",
                                   access = JsonProperty.Access.WRITE_ONLY )  private String  keystoreSecret        = "";
    @Setter @Getter
    @JsonProperty( value = "keystoreKeySecret",
                   access = JsonProperty.Access.WRITE_ONLY )                  private String  keystoreKeySecret     = "";
    @Setter @Getter @JsonProperty( "includeJdkCertificate" )                  private boolean includeJdkCertificate = false;
    @Setter @Getter @JsonProperty( "allowFilesystemLookup" )                  private boolean allowFilesystemLookup = false;
    @Setter @Getter @JsonProperty( "debugMode" )                              private boolean debugMode             = false;
    // @formatter:on

    public JksManagerArgs useQaResources()
    {
        String dwp = "4demandware";

        truststore = "certs/truststore.jks";
        truststoreSecret = dwp;

        keystore = "certs/qa-keys.jks";
        keystoreSecret = dwp;
        keystoreKeySecret = dwp;

        return this;
    }

    public JksManagerArgs configFile( String jsonName )
    {
        try (InputStream is = Function.getInputStreamFromName( jsonName, true ))
        {
            if ( is != null )
            {
                ObjectMapper   om       = new ObjectMapper();
                JksManagerArgs tempArgs = om.readValue( is, JksManagerArgs.class );
                if ( tempArgs != null )
                {
                    truststore = tempArgs.truststore;
                    truststoreSecret = tempArgs.truststoreSecret;
                    keystore = tempArgs.keystore;
                    keystoreSecret = tempArgs.keystoreSecret;
                    keystoreKeySecret = tempArgs.keystoreKeySecret;
                    includeJdkCertificate = tempArgs.includeJdkCertificate;
                    allowFilesystemLookup = tempArgs.allowFilesystemLookup;
                    debugMode = tempArgs.debugMode;
                }
            }
        }
        catch ( IOException e )
        {
            LOGGER.error( e );
        }

        return this;
    }

    public JksManagerArgs useProperties( Properties properties )
    {
        String p;

        if ( ( p = properties.getProperty( "security.truststore.file" ) ) != null )
        {
            truststore = p;
        }
        if ( ( p = properties.getProperty( "security.truststore.storepwd" ) ) != null )
        {
            truststoreSecret = p;
        }
        if ( ( p = properties.getProperty( "security.keystore.file" ) ) != null )
        {
            keystore = p;
        }
        if ( ( p = properties.getProperty( "security.keystore.storepwd" ) ) != null )
        {
            keystoreSecret = p;
        }
        if ( ( p = properties.getProperty( "security.keystore.keypwd" ) ) != null )
        {
            keystoreKeySecret = p;
        }

        return this;
    }

    public JksManagerArgs useArgs( String[] args )
    {
        List<String> argList = Arrays.asList( args );

        if ( argList.contains( "--trace" ) )
        {
            debugMode = true;
        }

        return this;
    }
}
