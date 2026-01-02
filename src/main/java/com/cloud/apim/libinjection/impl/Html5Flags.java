package com.cloud.apim.libinjection.impl;

/**
 * Enumeration of HTML5 parser initial states.
 * <p>
 * These flags determine the initial parsing context when analyzing HTML5 content
 * for XSS detection. Different contexts require different parsing rules.
 * </p>
 */
public enum Html5Flags {
    
    /**
     * Standard data state - parsing normal HTML content.
     */
    DATA_STATE,
    
    /**
     * Parsing an attribute value without quotes.
     */
    VALUE_NO_QUOTE,
    
    /**
     * Parsing an attribute value enclosed in single quotes.
     */
    VALUE_SINGLE_QUOTE,
    
    /**
     * Parsing an attribute value enclosed in double quotes.
     */
    VALUE_DOUBLE_QUOTE,
    
    /**
     * Parsing an attribute value enclosed in back quotes (backticks).
     */
    VALUE_BACK_QUOTE
}
