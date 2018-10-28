package me.steffen.http.fixture;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

public class HttpStatusCode
{
    private static final Map<Integer, String>  codeMap;
    private static final Map<Integer, Integer> unassignedIntervals;

    static
    {
        Map<Integer, String> aMap = new TreeMap<>();
        aMap.put( 100, "Continue [RFC7231, Section 6.2.1]" );
        aMap.put( 101, "Switching Protocols [RFC7231, Section 6.2.2]" );
        aMap.put( 102, "Processing [RFC2518]" );
        aMap.put( 200, "OK [RFC7231, Section 6.3.1]" );
        aMap.put( 201, "Created [RFC7231, Section 6.3.2]" );
        aMap.put( 202, "Accepted [RFC7231, Section 6.3.3]" );
        aMap.put( 203, "Non-Authoritative Information [RFC7231, Section 6.3.4]" );
        aMap.put( 204, "No Content [RFC7231, Section 6.3.5]" );
        aMap.put( 205, "Reset Content [RFC7231, Section 6.3.6]" );
        aMap.put( 206, "Partial Content [RFC7233, Section 4.1]" );
        aMap.put( 207, "Multi-Status [RFC4918]" );
        aMap.put( 208, "Already Reported [RFC5842]" );
        aMap.put( 226, "IM Used [RFC3229]" );
        aMap.put( 300, "Multiple Choices [RFC7231, Section 6.4.1]" );
        aMap.put( 301, "Moved Permanently [RFC7231, Section 6.4.2]" );
        aMap.put( 302, "Found [RFC7231, Section 6.4.3]" );
        aMap.put( 303, "See Other [RFC7231, Section 6.4.4]" );
        aMap.put( 304, "Not Modified [RFC7232, Section 4.1]" );
        aMap.put( 305, "Use Proxy [RFC7231, Section 6.4.5]" );
        aMap.put( 306, "(Unused) [RFC7231, Section 6.4.6]" );
        aMap.put( 307, "Temporary Redirect [RFC7231, Section 6.4.7]" );
        aMap.put( 308, "Permanent Redirect [RFC7538]" );
        aMap.put( 400, "Bad Request [RFC7231, Section 6.5.1]" );
        aMap.put( 401, "Unauthorized [RFC7235, Section 3.1]" );
        aMap.put( 402, "Payment Required [RFC7231, Section 6.5.2]" );
        aMap.put( 403, "Forbidden [RFC7231, Section 6.5.3]" );
        aMap.put( 404, "Not Found [RFC7231, Section 6.5.4]" );
        aMap.put( 405, "Method Not Allowed [RFC7231, Section 6.5.5]" );
        aMap.put( 406, "Not Acceptable [RFC7231, Section 6.5.6]" );
        aMap.put( 407, "Proxy Authentication Required [RFC7235, Section 3.2]" );
        aMap.put( 408, "Request Timeout [RFC7231, Section 6.5.7]" );
        aMap.put( 409, "Conflict [RFC7231, Section 6.5.8]" );
        aMap.put( 410, "Gone [RFC7231, Section 6.5.9]" );
        aMap.put( 411, "Length Required [RFC7231, Section 6.5.10]" );
        aMap.put( 412, "Precondition Failed [RFC7232, Section 4.2]" );
        aMap.put( 413, "Payload Too Large [RFC7231, Section 6.5.11]" );
        aMap.put( 414, "URI Too Long [RFC7231, Section 6.5.12]" );
        aMap.put( 415, "Unsupported Media Type [RFC7231, Section 6.5.13][RFC7694, Section 3]" );
        aMap.put( 416, "Range Not Satisfiable [RFC7233, Section 4.4]" );
        aMap.put( 417, "Expectation Failed [RFC7231, Section 6.5.14]" );
        aMap.put( 421, "Misdirected Request [RFC7540, Section 9.1.2]" );
        aMap.put( 422, "Unprocessable Entity [RFC4918]" );
        aMap.put( 423, "Locked [RFC4918]" );
        aMap.put( 424, "Failed Dependency [RFC4918]" );
        aMap.put( 426, "Upgrade Required [RFC7231, Section 6.5.15]" );
        aMap.put( 428, "Precondition Required [RFC6585]" );
        aMap.put( 429, "Too Many Requests [RFC6585]" );
        aMap.put( 431, "Request Header Fields Too Large [RFC6585]" );
        aMap.put( 451, "Unavailable For Legal Reasons [RFC7725]" );
        aMap.put( 500, "Internal Server Error [RFC7231, Section 6.6.1]" );
        aMap.put( 501, "Not Implemented [RFC7231, Section 6.6.2]" );
        aMap.put( 502, "Bad Gateway [RFC7231, Section 6.6.3]" );
        aMap.put( 503, "Service Unavailable [RFC7231, Section 6.6.4]" );
        aMap.put( 504, "Gateway Timeout [RFC7231, Section 6.6.5]" );
        aMap.put( 505, "HTTP Version Not Supported [RFC7231, Section 6.6.6]" );
        aMap.put( 506, "Variant Also Negotiates [RFC2295]" );
        aMap.put( 507, "Insufficient Storage [RFC4918]" );
        aMap.put( 508, "Loop Detected [RFC5842]" );
        aMap.put( 510, "Not Extended [RFC2774]" );
        aMap.put( 511, "Network Authentication Required [RFC6585]" );

        Map<Integer, Integer> uMap = new TreeMap<>();
        uMap.put( 103, 199 );
        uMap.put( 209, 225 );
        uMap.put( 227, 299 );
        uMap.put( 309, 399 );
        uMap.put( 418, 420 );
        uMap.put( 425, 425 );
        uMap.put( 427, 427 );
        uMap.put( 430, 430 );
        uMap.put( 432, 450 );
        uMap.put( 452, 499 );
        uMap.put( 509, 509 );
        uMap.put( 512, 599 );

        unassignedIntervals = Collections.unmodifiableMap( uMap );
        codeMap = Collections.unmodifiableMap( aMap );
    }

    private HttpStatusCode()
    {
        // static class only, no object needed
    }

    public static String explain( int code )
    {
        for ( Map.Entry<Integer, Integer> interval : unassignedIntervals.entrySet() )
        {
            if ( code >= interval.getKey() && code <= interval.getValue() )
            {
                return "Unassigned";
            }
        }

        return codeMap.getOrDefault( code, "unknown code" );
    }
}
