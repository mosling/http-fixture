package me.steffen.http.fixture;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import me.steffen.http.common.Function;

public class HttpAuth
{
    public static final String HEADER = "Authorization";

    @JsonProperty( "type" )
    @Getter
    @Setter
    private EnumAuthType authType = EnumAuthType.USER;

    @JsonProperty( "name" )
    @Getter
    @Setter
    private String authName;

    @JsonProperty( "password" )
    @Getter
    @Setter
    private String authPassword;

    @JsonProperty( "encode" )
    @Getter
    @Setter
    private boolean encode = true;

    @JsonIgnore private String httpAuthorization = "";

    public HttpAuth()
    {
        // Jackson need the default constructor
    }

    public HttpAuth( EnumAuthType authType, String authName, String authPassword, boolean encode )
    {
        this.authType = authType;
        this.authName = authName;
        this.authPassword = authPassword;
        this.encode = encode;
    }

    private void computeHttpAuthorization()
    {
        if ( null != authName && null != authType )
        {
            if ( authType != EnumAuthType.SESSION )
            {
                // default Authorization entry Basic, Bearer
                String x1 = authName;
                if ( authPassword != null && !authPassword.isEmpty() )
                {
                    x1 += ":" + authPassword;
                }

                httpAuthorization = authType.getHttpAuth() + " " + ( encode ? Function.base64Encoding( x1 ) : x1 );
            }
            else
            {
                // session identification using JSESSIONID cookie
                httpAuthorization = authType.getHttpAuth() + "=" + authName;
            }
        }
    }

    @Override
    public String toString()
    {
        return authType.toString() + " " + authName + ":" + authPassword + "  (with" + ( encode ? "" : "out" )
                + "encoding)";
    }

    public String getHttpAuthorization()
    {
        if ( httpAuthorization.isEmpty() )
        {
            computeHttpAuthorization();
        }

        return httpAuthorization;
    }
}
