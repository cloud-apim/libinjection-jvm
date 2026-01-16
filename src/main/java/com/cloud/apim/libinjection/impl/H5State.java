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
     * The starting position index of the current token in the input string.
     */
    public int token_start_pos;

    /**
     * The length of the current token.
     */
    public int token_len;

    /**
     * Returns the current token as a String.
     * This method creates a substring only when needed, avoiding unnecessary allocations
     * when only character access or index-based operations are required.
     *
     * @return the current token string, or empty string if no token
     */
    public String getTokenString() {
        if (token_len <= 0 || token_start_pos < 0 || token_start_pos >= s.length()) {
            return "";
        }
        int end = Math.min(token_start_pos + token_len, s.length());
        return s.substring(token_start_pos, end);
    }

    /**
     * Returns the character at the specified offset within the current token.
     * This avoids creating a substring just to access individual characters.
     *
     * @param offset the offset within the token (0-based)
     * @return the character at the specified offset
     */
    public char getTokenCharAt(int offset) {
        return s.charAt(token_start_pos + offset);
    }

    /**
     * Searches for a character within the current token.
     * This avoids creating a substring just to call indexOf.
     *
     * @param ch the character to search for
     * @return the index of the character within the token, or -1 if not found
     */
    public int tokenIndexOf(char ch) {
        int end = token_start_pos + token_len;
        for (int i = token_start_pos; i < end && i < s.length(); i++) {
            if (s.charAt(i) == ch) {
                return i - token_start_pos;
            }
        }
        return -1;
    }
    
    /**
     * The type of the current token being processed.
     */
    public Html5Type token_type;
}
