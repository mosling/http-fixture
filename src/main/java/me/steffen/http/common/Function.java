package me.steffen.http.common;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class Function
{
    private static final Logger LOGGER = LogManager.getLogger( Function.class );

    private Function()
    {
        // private default constructor, helper class offers only static methods
    }

    public static InputStream getInputStreamFromName( String name, boolean allowSystemAccess )
    {
        return getInputStreamFromName( name, allowSystemAccess, false );
    }

    /**
     * The method use ClassLoader().getResourceAsStream() to read a resource, that means NO leading slash
     * is needed to address the resources.
     *
     * @param name              first try open a resource, if not found try open a file if allowSystemAccess is true
     * @param allowSystemAccess also check the filesystem if there exists a file with this name and use it
     * @return InputStream or null if neither resource or file found
     */
    public static InputStream getInputStreamFromName( String name, boolean allowSystemAccess, boolean silent )
    {
        if ( null == name || name.isEmpty() )
        {
            return null;
        }

        String resName = name.trim();
        if ( resName.startsWith( "/" ) )
        {
            resName = "." + resName;
        }
        InputStream stream = Function.class.getClassLoader().getResourceAsStream( resName );
        if ( stream != null )
        {
            return stream;
        }

        if ( allowSystemAccess )
        {
            try
            {
                return new FileInputStream( new File( name ) );
            }
            catch ( FileNotFoundException ex )
            {
                if ( !silent )
                {
                    LOGGER.error( "can't found resource or file for name '{}'", name );
                }
            }
        }
        else
        {
            LOGGER.error( "can't found resource '{}'", name );
        }

        return null;
    }

    public static byte[] getHeaderFromName( String name, boolean allowSystemAccess, int countBytes )
    {
        try
        {
            InputStream is = getInputStreamFromName( name, allowSystemAccess );
            if ( null != is )
            {
                int    cb = Math.min( countBytes, is.available() );
                byte[] b  = new byte[cb];
                int    l  = is.read( b, 0, cb );
                if ( l != cb )
                {
                    LOGGER.warn( "read {} bytes only from {} (expected {} bytes)", l, name, cb );
                }
                is.close();
                return b;
            }
        }
        catch ( IOException e )
        {
            LOGGER.error( e );
        }

        return new byte[0];
    }

    /**
     * @param path the path that should exist or will be created
     * @return true if the path exists
     */
    public static boolean createFolderStructure( String path )
    {
        boolean bOk = true;
        if ( null != path && !path.isEmpty() )
        {
            File folder = new File( path );
            bOk = folder.isDirectory();
            if ( !bOk )
            {
                bOk = folder.mkdirs();
            }
            if ( !bOk )
            {
                LOGGER.error( "can't create folder '" + folder.getAbsolutePath() + "'" );
            }
        }
        return bOk;
    }

    public static File openExistingFile( String fileName )
    {
        if ( fileName == null || fileName.isEmpty() )
        {
            return null;
        }

        File nf = new File( fileName );
        if ( nf.exists() )
        {
            return nf;
        }
        else
        {
            LOGGER.error( "File '{}' doesn't exists", nf.getAbsoluteFile() );
        }

        return null;
    }

    public static String hexify( byte[] bytes )
    {

        char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        StringBuilder buf = new StringBuilder( bytes.length * 3 );

        for ( int i = 0; i < bytes.length; ++i )
        {
            if ( i > 0 )
            {
                buf.append( ':' );
            }
            buf.append( hexDigits[( bytes[i] & 0xf0 ) >> 4] );
            buf.append( hexDigits[bytes[i] & 0x0f] );
        }

        return buf.toString();
    }

    public static String getUtcString( Date d )
    {

        return DateTimeFormatter.ISO_INSTANT.format( d.toInstant() );
    }

    public static void logListElements( Level ll, String name, List<Object> objectList )
    {
        String t  = "                 ";
        String s  = "              |  ";
        int    nl = name.length();
        int    tl = t.length();
        if ( nl >= tl )
        {
            t = name.substring( 0, tl - 2 ) + "..";
        }
        else
        {
            t = t.substring( 0, tl - nl ) + name;
        }

        int idx     = 0;
        int lastIdx = objectList.size() - 1;
        for ( Object o : objectList
                .stream()
                .sorted( Comparator.comparing( Object::toString ) )
                .collect( Collectors.toList() ) )
        {
            LOGGER.log( ll, "{} : {}", ( 0 == idx || lastIdx == idx ) ? t : s, o.toString() );
            idx++;
        }
    }

    public static String base64Encoding( String txt )
    {
        return Base64.getEncoder().encodeToString( txt.getBytes( StandardCharsets.UTF_8 ) );
    }

    public static String encodeUrl( String s )
    {
        return URLEncoder.encode( s, StandardCharsets.UTF_8 ).replaceAll( "\\+", "%20" ).replaceAll( "\\*", "%2A" );
    }
}
