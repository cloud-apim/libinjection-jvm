package com.cloud.apim.libinjection.impl;

/**
 * Represents a single SQL token extracted during parsing.
 * <p>
 * This class stores information about a token including its position in the
 * input string, its type (keyword, operator, string, etc.), and its value.
 * </p>
 */
public class SqliToken {
    
    /**
     * Position of the token in the input string.
     */
    public int pos;
    
    /**
     * Length of the token.
     */
    public int len;
    
    /**
     * Count or occurrence number (used internally).
     */
    public int count;
    
    /**
     * Type of the token (e.g., 'k' for keyword, 's' for string, 'o' for operator).
     */
    public char type;
    
    /**
     * Opening quote character for string tokens ('\0' if not a quoted string).
     */
    public char str_open;
    
    /**
     * Closing quote character for string tokens ('\0' if not properly closed).
     */
    public char str_close;
    
    /**
     * The actual value/content of the token.
     */
    public char[] val;
    
    /**
     * Constructs a new SqliToken with default values.
     */
    public SqliToken() {
        this.val = new char[32];
        this.type = '\0';
        this.str_open = '\0';
        this.str_close = '\0';
        this.pos = 0;
        this.len = 0;
        this.count = 0;
    }
    
    /**
     * Clears all token data, resetting it to default values.
     */
    public void clear() {
        this.pos = 0;
        this.len = 0;
        this.count = 0;
        this.type = '\0';
        this.str_open = '\0';
        this.str_close = '\0';
        for (int i = 0; i < val.length; i++) {
            val[i] = '\0';
        }
    }
    
    /**
     * Copies data from another token into this token.
     * 
     * @param src the source token to copy from
     */
    public void copy(SqliToken src) {
        this.pos = src.pos;
        this.len = src.len;
        this.count = src.count;
        this.type = src.type;
        this.str_open = src.str_open;
        this.str_close = src.str_close;
        System.arraycopy(src.val, 0, this.val, 0, src.val.length);
    }
}
