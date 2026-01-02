package com.cloud.apim.libinjection;

import com.cloud.apim.libinjection.impl.LibInjectionXSS;

public class LibInjection {

    public static boolean isSQLi(String input) {
        return com.cloud.apim.libinjection.impl.LibInjectionSQLi.libinjection_is_sqli(input);
    }

    public static boolean isXSS(String input) {
        if (input == null) {
            return false;
        }
        return LibInjectionXSS.libinjection_xss(input, input.length());
    }
}