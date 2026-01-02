package com.cloud.apim.libinjection.impl;

import java.util.function.Function;

public class H5State {
    public String s;
    public int len;
    public int pos;
    public boolean is_close;
    public Function<H5State, Integer> state;
    public String token_start;
    public int token_len;
    public Html5Type token_type;
}
