package com.cloud.apim.libinjection.impl;

public class SqliToken {
    public int pos;
    public int len;
    public int count;
    public char type;
    public char str_open;
    public char str_close;
    public char[] val;
    
    public SqliToken() {
        this.val = new char[32];
        this.type = '\0';
        this.str_open = '\0';
        this.str_close = '\0';
        this.pos = 0;
        this.len = 0;
        this.count = 0;
    }
    
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
