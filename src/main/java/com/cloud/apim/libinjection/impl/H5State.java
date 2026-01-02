package com.cloud.apim.libinjection.impl;

import java.util.function.Function;

/**
 * Represents the state of the HTML5 parser.
 * <p>
 * This class maintains the current parsing state while processing HTML5 content
 * for XSS detection. It tracks the position in the input string, the current
 * parsing state function, and information about the current token being processed.
 * </p>
 */
public class H5State {
    
    /**
     * The input string being parsed.
     */
    public String s;
    
    /**
     * The length of the input string.
     */
    public int len;
    
    /**
     * The current position in the input string.
     */
    public int pos;
    
    /**
     * Indicates whether the current tag is a closing tag.
     */
    public boolean is_close;
    
    /**
     * The current state function for the HTML5 state machine.
     * This function processes the next character(s) and returns the next state.
     */
    public Function<H5State, Integer> state;
    
    /**
     * The starting position of the current token in the input string.
     */
    public String token_start;
    
    /**
     * The length of the current token.
     */
    public int token_len;
    
    /**
     * The type of the current token being processed.
     */
    public Html5Type token_type;
}
