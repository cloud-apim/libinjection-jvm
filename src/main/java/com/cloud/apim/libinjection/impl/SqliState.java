package com.cloud.apim.libinjection.impl;

/**
 * Represents the state of the SQL injection detection parser.
 * <p>
 * This class maintains the parsing state while analyzing SQL input for injection
 * patterns. It tracks tokens, fingerprints, and various statistics about the
 * parsed content.
 * </p>
 */
public class SqliState {
    
    /**
     * The input string being analyzed.
     */
    public String s;
    
    /**
     * The length of the input string.
     */
    public int slen;
    
    /**
     * Parsing flags (quote type and SQL dialect).
     */
    public int flags;
    
    /**
     * Current position in the input string.
     */
    public int pos;
    
    /**
     * Array of tokens extracted from the input.
     */
    public SqliToken[] tokenvec;
    
    /**
     * The current token being processed.
     */
    public SqliToken current;
    
    /**
     * The fingerprint representing the token pattern.
     */
    public char[] fingerprint;
    
    /**
     * Reason code for detection result.
     */
    public int reason;
    
    /**
     * Count of double-dash comments with whitespace (-- ).
     */
    public int stats_comment_ddw;
    
    /**
     * Count of double-dash comments without whitespace (--).
     */
    public int stats_comment_ddx;
    
    /**
     * Count of C-style comments (/* *\/).
     */
    public int stats_comment_c;
    
    /**
     * Count of hash comments (#).
     */
    public int stats_comment_hash;
    
    /**
     * Count of token folding operations performed.
     */
    public int stats_folds;
    
    /**
     * Total number of tokens extracted.
     */
    public int stats_tokens;
    
    /**
     * Constructs a new SqliState with initialized token vector and fingerprint.
     */
    public SqliState() {
        this.tokenvec = new SqliToken[8];
        for (int i = 0; i < 8; i++) {
            this.tokenvec[i] = new SqliToken();
        }
        this.fingerprint = new char[8];
        this.current = this.tokenvec[0];
    }
}
