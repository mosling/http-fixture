package me.steffen.http.fixture;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Accessors( fluent = true )
public class HttpClientArgs
{
    /**
     * This String is used when the client has to present a client certificate during
     * server communication. The certificates itself stored into {@link me.steffen.http.security.JksManager}.
     * To select the right certificate for the server we search for an entry that starts with this alias followed by an
     * underline and the domain of the server. If nothing found this alias is used.
     */
    @Setter @Getter private String  clientCertAlias              = "authz_rpc";
    /**
     * The config file is a json file which contains lists for connections, authorizations and preconfigured addresses,
     * this is very useful to start the client with a number of existing connections and so on. But everything can
     * later added by some methods.
     */
    @Setter @Getter private String  configFile                   = "default-config.json";
    /**
     * During a server communication the client has the possibility to verify the hostname of the server. For this
     * we have a number of different actions:
     * <ul>
     * <li>logging: show information about the host an returns true</li>
     * <li>noop: returns true and show nothing</li>
     * <li>default: the default java hostname verifier which checks the server certificate</li>
     * </ul>
     */
    @Setter @Getter private String  hostnameVerifier             = "logging";
    /**
     * For every request we can set a timeout, this timeout is configured for all request using this {@link HttpClient}.
     * The default is 10 seconds, which should be enough for each normal http operation.
     */
    @Setter @Getter private int     requestTimeoutMs             = 10000;
    /**
     * During a http request the server can send a redirect with an Location header. With this argument the behavior
     * for handling this can be defined. The default case is to do nothing. But set the argument to true the process
     * follows the redirection and the result is the last response without a redirection.
     */
    @Setter @Getter private boolean enableRedirect               = false;
    /**
     * The default case for the used HttpClient is that the object simulates the same cookie handling as a browser.
     * By default this behavior isn't enabled, so we have full control over all response headers.
     */
    @Setter @Getter private boolean disableCookieHandling        = true;
    /**
     * The best practice is to have separate keystore files for certificates and for private keys. In some case all
     * is stored in a single keystore. If so set this argument to true but it is not recommended.
     */
    @Setter @Getter private boolean keystoreContainsCertificates = false;
    /**
     * The default is that the client has to trust the server using a certificate. In some rare cases and for tests
     * this can be disabled by settings this to true. <b>This should be forbidden for every production services.</b>
     */
    @Setter @Getter private boolean trustAll                     = false;
}
