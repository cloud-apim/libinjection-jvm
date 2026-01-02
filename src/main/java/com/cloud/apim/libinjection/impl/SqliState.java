package com.cloud.apim.libinjection.impl;

public class SqliState {
    public String s;
    public int slen;
    public int flags;
    public int pos;
    public SqliToken[] tokenvec;
    public SqliToken current;
    public char[] fingerprint;
    public int reason;
    public int stats_comment_ddw;
    public int stats_comment_ddx;
    public int stats_comment_c;
    public int stats_comment_hash;
    public int stats_folds;
    public int stats_tokens;
    
    public SqliState() {
        this.tokenvec = new SqliToken[8];
        for (int i = 0; i < 8; i++) {
            this.tokenvec[i] = new SqliToken();
        }
        this.fingerprint = new char[8];
        this.current = this.tokenvec[0];
    }
}
