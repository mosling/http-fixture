package me.steffen.http.fixture;

import lombok.Getter;

@SuppressWarnings( "unused" )
public enum EnumAuthType
{

    CLIENT( HttpAuth.HEADER, "Basic", true ),
    USER( HttpAuth.HEADER, "Basic", true ),
    SESSION( "Cookie", "JSESSIONID", false ),
    VAULT( "X-Vault-Token", "", true ),
    BEARER( HttpAuth.HEADER, "Bearer", true );

    @Getter private final String authHeaderField;

    @Getter private final String httpAuth;

    @Getter private final boolean override;

    EnumAuthType( String s1, String s2, boolean b1 )
    {
        authHeaderField = s1;
        httpAuth = s2;
        override = b1;
    }

    @Override
    public String toString()
    {
        return authHeaderField + "(" + ( override ? "with" : "without" ) + "override): " + httpAuth;
    }

}
