package com.cloud.apim.libinjection;

import com.cloud.apim.libinjection.impl.LibInjectionXSS;

/**
 * Main entry point for the libinjection library.
 * <p>
 * This class provides static methods to detect SQL injection (SQLi) and 
 * Cross-Site Scripting (XSS) attacks in user input strings.
 * </p>
 * <p>
 * The library is a Java port of the libinjection C library, which uses 
 * pattern matching and fingerprinting techniques to identify malicious payloads.
 * </p>
 * 
 * @author libinjection-jvm
 * @version 1.0
 */
public class LibInjection {

    /**
     * Detects SQL injection attempts in the provided input string.
     * <p>
     * This method analyzes the input for SQL injection patterns using tokenization
     * and fingerprinting techniques. It supports multiple SQL dialects including
     * ANSI SQL and MySQL.
     * </p>
     * 
     * @param input the string to analyze for SQL injection patterns
     * @return {@code true} if SQL injection is detected, {@code false} otherwise
     */
    public static boolean isSQLi(String input) {
        return com.cloud.apim.libinjection.impl.LibInjectionSQLi.libinjection_is_sqli(input);
    }

    /**
     * Detects Cross-Site Scripting (XSS) attempts in the provided input string.
     * <p>
     * This method analyzes the input for XSS patterns by parsing it as HTML5
     * and checking for dangerous tags, attributes, and URLs that could be used
     * to execute malicious scripts.
     * </p>
     * 
     * @param input the string to analyze for XSS patterns
     * @return {@code true} if XSS is detected, {@code false} otherwise.
     *         Returns {@code false} if input is {@code null}
     */
    public static boolean isXSS(String input) {
        if (input == null) {
            return false;
        }
        return LibInjectionXSS.libinjection_xss(input, input.length());
    }
}