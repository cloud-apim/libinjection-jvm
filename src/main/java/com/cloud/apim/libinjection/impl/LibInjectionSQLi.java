package com.cloud.apim.libinjection.impl;

/**
 * SQL injection detection implementation.
 * <p>
 * This class provides methods to detect SQL injection attacks by tokenizing
 * SQL input and generating fingerprints that are matched against known
 * malicious patterns. It supports both ANSI SQL and MySQL dialects.
 * </p>
 * <p>
 * The detection process involves:
 * <ul>
 * <li>Tokenizing the input into SQL tokens (keywords, operators, strings, etc.)</li>
 * <li>Generating a fingerprint from the token sequence</li>
 * <li>Checking the fingerprint against blacklists and whitelists</li>
 * <li>Analyzing token patterns for suspicious structures</li>
 * </ul>
 * </p>
 */
public class LibInjectionSQLi {
    
    private static final int LIBINJECTION_SQLI_TOKEN_SIZE = 32;
    private static final int LIBINJECTION_SQLI_MAX_TOKENS = 5;
    
    private static final char CHAR_NULL = '\0';
    private static final char CHAR_SINGLE = '\'';
    private static final char CHAR_DOUBLE = '"';
    private static final char CHAR_TICK = '`';
    
    public static final int FLAG_NONE = 0;
    public static final int FLAG_QUOTE_NONE = 1;
    public static final int FLAG_QUOTE_SINGLE = 2;
    public static final int FLAG_QUOTE_DOUBLE = 4;
    public static final int FLAG_SQL_ANSI = 8;
    public static final int FLAG_SQL_MYSQL = 16;
    
    public static final int LOOKUP_WORD = 1;
    public static final int LOOKUP_TYPE = 2;
    public static final int LOOKUP_OPERATOR = 3;
    public static final int LOOKUP_FINGERPRINT = 4;
    
    private static final char TYPE_NONE = '\0';
    private static final char TYPE_KEYWORD = 'k';
    private static final char TYPE_UNION = 'U';
    private static final char TYPE_GROUP = 'B';
    private static final char TYPE_EXPRESSION = 'E';
    private static final char TYPE_SQLTYPE = 't';
    private static final char TYPE_FUNCTION = 'f';
    private static final char TYPE_BAREWORD = 'n';
    private static final char TYPE_NUMBER = '1';
    private static final char TYPE_VARIABLE = 'v';
    private static final char TYPE_STRING = 's';
    private static final char TYPE_OPERATOR = 'o';
    private static final char TYPE_LOGIC_OPERATOR = '&';
    private static final char TYPE_COMMENT = 'c';
    private static final char TYPE_COLLATE = 'A';
    private static final char TYPE_LEFTPARENS = '(';
    private static final char TYPE_RIGHTPARENS = ')';
    private static final char TYPE_LEFTBRACE = '{';
    private static final char TYPE_RIGHTBRACE = '}';
    private static final char TYPE_DOT = '.';
    private static final char TYPE_COMMA = ',';
    private static final char TYPE_COLON = ':';
    private static final char TYPE_SEMICOLON = ';';
    private static final char TYPE_TSQL = 'T';
    private static final char TYPE_UNKNOWN = '?';
    private static final char TYPE_EVIL = 'X';
    private static final char TYPE_FINGERPRINT = 'F';
    private static final char TYPE_BACKSLASH = '\\';
    
    private static boolean ISDIGIT(char a) {
        return a >= '0' && a <= '9';
    }
    
    private static char flag2delim(int flag) {
        if ((flag & FLAG_QUOTE_SINGLE) != 0) {
            return CHAR_SINGLE;
        } else if ((flag & FLAG_QUOTE_DOUBLE) != 0) {
            return CHAR_DOUBLE;
        } else {
            return CHAR_NULL;
        }
    }
    
    private static int memchr2(String haystack, int offset, int len, char c0, char c1) {
        if (len < 2) {
            return -1;
        }
        int last = offset + len - 1;
        for (int i = offset; i < last; i++) {
            if (haystack.charAt(i) == c0 && haystack.charAt(i + 1) == c1) {
                return i;
            }
        }
        return -1;
    }
    
    private static int my_memmem(String haystack, int hstart, int hlen, String needle) {
        if (needle.length() == 0 || hlen < needle.length()) {
            return -1;
        }
        int last = hstart + hlen - needle.length();
        for (int i = hstart; i <= last; i++) {
            if (haystack.charAt(i) == needle.charAt(0)) {
                boolean match = true;
                for (int j = 1; j < needle.length(); j++) {
                    if (haystack.charAt(i + j) != needle.charAt(j)) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return i;
                }
            }
        }
        return -1;
    }
    
    private static int strlenspn(String s, int offset, int len, String accept) {
        for (int i = 0; i < len; i++) {
            if (accept.indexOf(s.charAt(offset + i)) == -1) {
                return i;
            }
        }
        return len;
    }
    
    private static int strlencspn(String s, int offset, int len, String reject) {
        for (int i = 0; i < len; i++) {
            if (reject.indexOf(s.charAt(offset + i)) != -1) {
                return i;
            }
        }
        return len;
    }
    
    private static boolean char_is_white(char ch) {
        return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\u000B' || 
               ch == '\f' || ch == '\r' || ch == '\u00A0' || ch == '\0';
    }
    
    private static int cstrcasecmp(String a, String b, int n) {
        for (int i = 0; i < n && i < a.length(); i++) {
            char ca = a.charAt(i);
            char cb = i < b.length() ? b.charAt(i) : '\0';
            if (cb >= 'a' && cb <= 'z') {
                cb = (char)(cb - 0x20);
            }
            if (ca != cb) {
                return ca - cb;
            } else if (ca == '\0') {
                return -1;
            }
        }
        return (a.length() == n) ? 0 : 1;
    }
    
    private static boolean streq(String a, String b) {
        return a.equals(b);
    }
    
    /**
     * Binary search for a keyword in the keyword array.
     * 
     * @param key the keyword to search for
     * @param len the length of the keyword
     * @param keywords the keyword array
     * @return the keyword type, or '\0' if not found
     */
    private static char bsearch_keyword_type(String key, int len, SqliKeywords.Keyword[] keywords) {
        int left = 0;
        int right = keywords.length - 1;
        
        while (left < right) {
            int pos = (left + right) >>> 1;
            int cmp = cstrcasecmp(keywords[pos].word, key, len);
            if (cmp < 0) {
                left = pos + 1;
            } else {
                right = pos;
            }
        }
        
        if (left == right && cstrcasecmp(keywords[left].word, key, len) == 0) {
            return keywords[left].type;
        }
        return CHAR_NULL;
    }
    
    /**
     * Checks if a word is a SQL keyword.
     * 
     * @param key the word to check
     * @param len the length of the word
     * @return the keyword type character, or '\0' if not a keyword
     */
    private static char is_keyword(String key, int len) {
        return bsearch_keyword_type(key, len, SqliKeywords.SQL_KEYWORDS);
    }
    
    /**
     * Main entry point for SQL injection detection.
     * <p>
     * Analyzes the input string for SQL injection patterns. Returns false
     * for null or empty input.
     * </p>
     * 
     * @param input the string to analyze for SQL injection
     * @return true if SQL injection is detected, false otherwise
     */
    public static boolean libinjection_is_sqli(String input) {
        if (input == null || input.length() == 0) {
            return false;
        }
        
        SqliState sql_state = new SqliState();
        libinjection_sqli_init(sql_state, input, input.length(), 0);
        return libinjection_is_sqli(sql_state);
    }
    
    /**
     * Initializes the SQL injection detection state.
     * 
     * @param sf the state object to initialize
     * @param s the input string
     * @param len the length of the input
     * @param flags parsing flags (quote type and SQL dialect)
     */
    private static void libinjection_sqli_init(SqliState sf, String s, int len, int flags) {
        if (flags == 0) {
            flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI;
        }
        
        sf.s = s;
        sf.slen = len;
        sf.flags = flags;
        sf.pos = 0;
        sf.current = sf.tokenvec[0];
        sf.stats_comment_ddw = 0;
        sf.stats_comment_ddx = 0;
        sf.stats_comment_c = 0;
        sf.stats_comment_hash = 0;
        sf.stats_folds = 0;
        sf.stats_tokens = 0;
        sf.reason = 0;
        for (int i = 0; i < sf.fingerprint.length; i++) {
            sf.fingerprint[i] = '\0';
        }
    }
    
    /**
     * Core SQL injection detection logic.
     * <p>
     * Tests the input with multiple parsing strategies (different quote types
     * and SQL dialects) to detect injection attempts.
     * </p>
     * 
     * @param sql_state the initialized state object
     * @return true if SQL injection is detected, false otherwise
     */
    private static boolean libinjection_is_sqli(SqliState sql_state) {
        String s = sql_state.s;
        int slen = sql_state.slen;
        
        if (slen == 0) {
            return false;
        }
        
        libinjection_sqli_fingerprint(sql_state, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
        if (libinjection_sqli_check_fingerprint(sql_state)) {
            return true;
        } else if (reparse_as_mysql(sql_state)) {
            libinjection_sqli_fingerprint(sql_state, FLAG_QUOTE_NONE | FLAG_SQL_MYSQL);
            if (libinjection_sqli_check_fingerprint(sql_state)) {
                return true;
            }
        }
        
        if (s.indexOf(CHAR_SINGLE) != -1) {
            libinjection_sqli_fingerprint(sql_state, FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI);
            if (libinjection_sqli_check_fingerprint(sql_state)) {
                return true;
            } else if (reparse_as_mysql(sql_state)) {
                libinjection_sqli_fingerprint(sql_state, FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL);
                if (libinjection_sqli_check_fingerprint(sql_state)) {
                    return true;
                }
            }
        }
        
        if (s.indexOf(CHAR_DOUBLE) != -1) {
            libinjection_sqli_fingerprint(sql_state, FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL);
            if (libinjection_sqli_check_fingerprint(sql_state)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Determines if the input should be reparsed as MySQL dialect.
     * <p>
     * MySQL has specific comment styles that may indicate injection.
     * </p>
     * 
     * @param sql_state the state object
     * @return true if MySQL-specific patterns are detected
     */
    private static boolean reparse_as_mysql(SqliState sql_state) {
        return sql_state.stats_comment_ddx > 0 || sql_state.stats_comment_hash > 0;
    }
    
    /**
     * Generates a fingerprint from the tokenized input.
     * <p>
     * The fingerprint is a string of characters where each character represents
     * a token type (e.g., 'k' for keyword, 's' for string, 'o' for operator).
     * </p>
     * 
     * @param sql_state the state object
     * @param flags parsing flags
     */
    private static void libinjection_sqli_fingerprint(SqliState sql_state, int flags) {
        libinjection_sqli_reset(sql_state, flags);
        int tlen = libinjection_sqli_fold(sql_state);
        
        if (tlen > 2 &&
            sql_state.tokenvec[tlen-1].type == TYPE_BAREWORD &&
            sql_state.tokenvec[tlen-1].str_open == CHAR_TICK &&
            sql_state.tokenvec[tlen-1].len == 0 &&
            sql_state.tokenvec[tlen-1].str_close == CHAR_NULL) {
            sql_state.tokenvec[tlen-1].type = TYPE_COMMENT;
        }
        
        for (int i = 0; i < tlen; ++i) {
            sql_state.fingerprint[i] = sql_state.tokenvec[i].type;
        }
        sql_state.fingerprint[tlen] = CHAR_NULL;
        
        String fpStr = new String(sql_state.fingerprint, 0, tlen);
        if (fpStr.indexOf(TYPE_EVIL) != -1) {
            for (int i = 0; i < sql_state.fingerprint.length; i++) {
                sql_state.fingerprint[i] = '\0';
            }
            for (int i = 0; i < sql_state.tokenvec[0].val.length; i++) {
                sql_state.tokenvec[0].val[i] = '\0';
            }
            sql_state.fingerprint[0] = TYPE_EVIL;
            sql_state.tokenvec[0].type = TYPE_EVIL;
            sql_state.tokenvec[0].val[0] = TYPE_EVIL;
            sql_state.tokenvec[1].type = CHAR_NULL;
        }
    }
    
    /**
     * Resets the state for reparsing with different flags.
     * 
     * @param sf the state object
     * @param flags the new parsing flags
     */
    private static void libinjection_sqli_reset(SqliState sf, int flags) {
        if (flags == 0) {
            flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI;
        }
        String s = sf.s;
        int slen = sf.slen;
        libinjection_sqli_init(sf, s, slen, flags);
    }
    
    /**
     * Checks if the fingerprint matches known SQL injection patterns.
     * 
     * @param sql_state the state object with generated fingerprint
     * @return true if the fingerprint matches a known attack pattern
     */
    private static boolean libinjection_sqli_check_fingerprint(SqliState sql_state) {
        return libinjection_sqli_blacklist(sql_state) && 
               libinjection_sqli_not_whitelist(sql_state);
    }
    
    /**
     * Checks if the fingerprint is in the blacklist.
     * 
     * @param sql_state the state object
     * @return true if the fingerprint is blacklisted
     */
    private static boolean libinjection_sqli_blacklist(SqliState sql_state) {
        char[] fp2 = new char[8];
        String fpStr = new String(sql_state.fingerprint).replace("\0", "");
        int len = fpStr.length();
        
        if (len < 1) {
            return false;
        }
        
        fp2[0] = '0';
        for (int i = 0; i < len; ++i) {
            char ch = fpStr.charAt(i);
            if (ch >= 'a' && ch <= 'z') {
                ch = (char)(ch - 0x20);
            }
            fp2[i+1] = ch;
        }
        fp2[len+1] = '\0';
        
        String fp2Str = new String(fp2, 0, len + 1);
        return is_keyword(fp2Str, len + 1) == TYPE_FINGERPRINT;
    }
    
    /**
     * Checks if the fingerprint is NOT in the whitelist.
     * <p>
     * This method applies additional heuristics to filter out false positives
     * by checking for legitimate SQL patterns.
     * </p>
     * 
     * @param sql_state the state object
     * @return true if the pattern is suspicious (not whitelisted)
     */
    private static boolean libinjection_sqli_not_whitelist(SqliState sql_state) {
        String fpStr = new String(sql_state.fingerprint).replace("\0", "");
        int tlen = fpStr.length();
        
        if (tlen > 1 && sql_state.fingerprint[tlen-1] == TYPE_COMMENT) {
            if (my_memmem(sql_state.s, 0, sql_state.slen, "sp_password") != -1) {
                return true;
            }
        }
        
        switch (tlen) {
        case 2: {
            if (sql_state.fingerprint[1] == TYPE_UNION) {
                if (sql_state.stats_tokens == 2) {
                    return false;
                } else {
                    return true;
                }
            }
            if (sql_state.tokenvec[1].val[0] == '#') {
                return false;
            }
            if (sql_state.tokenvec[0].type == TYPE_BAREWORD &&
                sql_state.tokenvec[1].type == TYPE_COMMENT &&
                sql_state.tokenvec[1].val[0] != '/') {
                return false;
            }
            if (sql_state.tokenvec[0].type == TYPE_NUMBER &&
                sql_state.tokenvec[1].type == TYPE_COMMENT &&
                sql_state.tokenvec[1].val[0] == '/') {
                return true;
            }
            if (sql_state.tokenvec[0].type == TYPE_NUMBER &&
                sql_state.tokenvec[1].type == TYPE_COMMENT) {
                if (sql_state.stats_tokens > 2) {
                    return true;
                }
                if (sql_state.tokenvec[0].len < sql_state.slen) {
                    char ch = sql_state.s.charAt(sql_state.tokenvec[0].len);
                    if (ch <= 32) {
                        return true;
                    }
                    if (ch == '/' && sql_state.tokenvec[0].len + 1 < sql_state.slen && 
                        sql_state.s.charAt(sql_state.tokenvec[0].len + 1) == '*') {
                        return true;
                    }
                    if (ch == '-' && sql_state.tokenvec[0].len + 1 < sql_state.slen && 
                        sql_state.s.charAt(sql_state.tokenvec[0].len + 1) == '-') {
                        return true;
                    }
                }
                return false;
            }
            if ((sql_state.tokenvec[1].len > 2) && sql_state.tokenvec[1].val[0] == '-') {
                return false;
            }
            break;
        }
        case 3: {
            if (streq(fpStr, "sos") || streq(fpStr, "s&s")) {
                if ((sql_state.tokenvec[0].str_open == CHAR_NULL) &&
                    (sql_state.tokenvec[2].str_close == CHAR_NULL) &&
                    (sql_state.tokenvec[0].str_close == sql_state.tokenvec[2].str_open)) {
                    return true;
                }
                if (sql_state.stats_tokens == 3) {
                    return false;
                }
                return false;
            } else if (streq(fpStr, "s&n") || streq(fpStr, "n&1") ||
                       streq(fpStr, "1&1") || streq(fpStr, "1&v") ||
                       streq(fpStr, "1&s")) {
                if (sql_state.stats_tokens == 3) {
                    return false;
                }
            } else if (sql_state.tokenvec[1].type == TYPE_KEYWORD) {
                String tokenVal = new String(sql_state.tokenvec[1].val, 0, sql_state.tokenvec[1].len);
                if ((sql_state.tokenvec[1].len < 5) ||
                    cstrcasecmp("INTO", tokenVal, 4) != 0) {
                    return false;
                }
            }
            break;
        }
        case 4:
        case 5: {
            break;
        }
        }
        
        return true;
    }
    
    /**
     * Folds (collapses) consecutive tokens to simplify the fingerprint.
     * <p>
     * This process removes noise and focuses on the essential structure
     * of the SQL statement.
     * </p>
     * 
     * @param sf the state object
     * @return the number of tokens after folding
     */
    private static int libinjection_sqli_fold(SqliState sf) {
        int pos = 0;
        int left = 0;
        boolean more = true;
        
        sf.current = sf.tokenvec[0];
        while (more) {
            more = libinjection_sqli_tokenize(sf);
            if (!(sf.current.type == TYPE_COMMENT ||
                  sf.current.type == TYPE_LEFTPARENS ||
                  sf.current.type == TYPE_SQLTYPE ||
                  st_is_unary_op(sf.current))) {
                break;
            }
        }
        
        if (!more) {
            return 0;
        } else {
            pos += 1;
        }
        
        while (true) {
            if (!more || left >= LIBINJECTION_SQLI_MAX_TOKENS) {
                left = pos;
                break;
            }
            
            while (more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && (pos - left) < 2) {
                sf.current = sf.tokenvec[pos];
                more = libinjection_sqli_tokenize(sf);
                if (more) {
                    if (sf.current.type != TYPE_COMMENT) {
                        pos += 1;
                    }
                }
            }
            
            if (pos - left < 2) {
                left = pos;
                continue;
            }
            
            if (sf.tokenvec[left].type == TYPE_STRING && sf.tokenvec[left+1].type == TYPE_STRING) {
                pos -= 1;
                sf.stats_folds += 1;
                continue;
            }
            
            left += 1;
        }
        
        if (left > LIBINJECTION_SQLI_MAX_TOKENS) {
            left = LIBINJECTION_SQLI_MAX_TOKENS;
        }
        
        return left;
    }
    
    /**
     * Extracts the next token from the input.
     * <p>
     * Identifies SQL keywords, operators, strings, numbers, comments, etc.
     * </p>
     * 
     * @param sf the state object
     * @return true if a token was extracted, false if end of input
     */
    private static boolean libinjection_sqli_tokenize(SqliState sf) {
        if (sf.slen == 0) {
            return false;
        }
        
        sf.current.clear();
        
        if (sf.pos == 0 && (sf.flags & (FLAG_QUOTE_SINGLE | FLAG_QUOTE_DOUBLE)) != 0) {
            sf.pos = parse_string_core(sf.s, sf.slen, 0, sf.current, flag2delim(sf.flags), 0);
            sf.stats_tokens += 1;
            return true;
        }
        
        while (sf.pos < sf.slen) {
            char ch = sf.s.charAt(sf.pos);
            
            if (char_is_white(ch)) {
                sf.pos = sf.pos + 1;
                continue;
            }
            
            if (ch == '\'' || ch == '"') {
                sf.pos = parse_string_core(sf.s, sf.slen, sf.pos, sf.current, ch, 1);
                sf.stats_tokens += 1;
                return true;
            }
            
            if (ch == '-' && sf.pos + 1 < sf.slen && sf.s.charAt(sf.pos + 1) == '-') {
                if (sf.pos + 2 < sf.slen && char_is_white(sf.s.charAt(sf.pos + 2))) {
                    sf.pos = parse_eol_comment(sf);
                    sf.stats_comment_ddw += 1;
                    sf.stats_tokens += 1;
                    return true;
                } else if (sf.pos + 2 == sf.slen) {
                    sf.pos = parse_eol_comment(sf);
                    sf.stats_comment_ddw += 1;
                    sf.stats_tokens += 1;
                    return true;
                }
            }
            
            if (ch == '#') {
                if ((sf.flags & FLAG_SQL_MYSQL) != 0) {
                    sf.pos = parse_eol_comment(sf);
                    sf.stats_comment_hash += 1;
                    sf.stats_tokens += 1;
                    return true;
                }
            }
            
            if (ch == '/' && sf.pos + 1 < sf.slen && sf.s.charAt(sf.pos + 1) == '*') {
                int endpos = memchr2(sf.s, sf.pos + 2, sf.slen - sf.pos - 2, '*', '/');
                if (endpos == -1) {
                    st_assign(sf.current, TYPE_COMMENT, sf.pos, sf.slen - sf.pos, sf.s.substring(sf.pos));
                    sf.pos = sf.slen;
                } else {
                    int clen = endpos - sf.pos + 2;
                    st_assign(sf.current, TYPE_COMMENT, sf.pos, clen, sf.s.substring(sf.pos, sf.pos + clen));
                    sf.pos = endpos + 2;
                }
                sf.stats_comment_c += 1;
                sf.stats_tokens += 1;
                return true;
            }
            
            if (ISDIGIT(ch) || (ch == '.' && sf.pos + 1 < sf.slen && ISDIGIT(sf.s.charAt(sf.pos + 1)))) {
                sf.pos = parse_number(sf);
                sf.stats_tokens += 1;
                return true;
            }
            
            if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_') {
                sf.pos = parse_word(sf);
                sf.stats_tokens += 1;
                return true;
            }
            
            if (ch == '(' || ch == ')' || ch == ',' || ch == ';') {
                st_assign_char(sf.current, ch, sf.pos, 1, ch);
                sf.pos += 1;
                sf.stats_tokens += 1;
                return true;
            }
            
            st_assign_char(sf.current, TYPE_OPERATOR, sf.pos, 1, ch);
            sf.pos += 1;
            sf.stats_tokens += 1;
            return true;
        }
        
        return false;
    }
    
    /**
     * Parses a quoted string token.
     * 
     * @param cs the input string
     * @param len the length of the input
     * @param pos the current position
     * @param st the token to populate
     * @param delim the quote delimiter
     * @param offset offset from position
     * @return the new position after parsing
     */
    private static int parse_string_core(String cs, int len, int pos, SqliToken st, char delim, int offset) {
        int qpos = cs.indexOf(delim, pos + offset);
        
        if (offset > 0) {
            st.str_open = delim;
        } else {
            st.str_open = CHAR_NULL;
        }
        
        while (true) {
            if (qpos == -1) {
                st_assign(st, TYPE_STRING, pos + offset, len - pos - offset, cs.substring(pos + offset));
                st.str_close = CHAR_NULL;
                return len;
            } else if (is_backslash_escaped(cs, qpos - 1, pos + offset)) {
                qpos = cs.indexOf(delim, qpos + 1);
                continue;
            } else if (is_double_delim_escaped(cs, qpos, len)) {
                qpos = cs.indexOf(delim, qpos + 2);
                continue;
            } else {
                st_assign(st, TYPE_STRING, pos + offset, qpos - (pos + offset), cs.substring(pos + offset, qpos));
                st.str_close = delim;
                return qpos + 1;
            }
        }
    }
    
    /**
     * Checks if a character is backslash-escaped.
     * 
     * @param s the string
     * @param end the position to check
     * @param start the start position
     * @return true if the character is escaped
     */
    private static boolean is_backslash_escaped(String s, int end, int start) {
        int count = 0;
        for (int ptr = end; ptr >= start; ptr--) {
            if (s.charAt(ptr) != '\\') {
                break;
            }
            count++;
        }
        return (count & 1) == 1;
    }
    
    /**
     * Checks if a delimiter is escaped by doubling (e.g., '' or "").
     * 
     * @param s the string
     * @param cur the current position
     * @param end the end position
     * @return true if the delimiter is doubled
     */
    private static boolean is_double_delim_escaped(String s, int cur, int end) {
        return (cur + 1) < end && s.charAt(cur + 1) == s.charAt(cur);
    }
    
    /**
     * Parses an end-of-line comment (-- or #).
     * 
     * @param sf the state object
     * @return the new position after parsing
     */
    private static int parse_eol_comment(SqliState sf) {
        int endpos = sf.s.indexOf('\n', sf.pos);
        if (endpos == -1) {
            st_assign(sf.current, TYPE_COMMENT, sf.pos, sf.slen - sf.pos, sf.s.substring(sf.pos));
            return sf.slen;
        } else {
            st_assign(sf.current, TYPE_COMMENT, sf.pos, endpos - sf.pos, sf.s.substring(sf.pos, endpos));
            return endpos + 1;
        }
    }
    
    /**
     * Parses a numeric literal.
     * 
     * @param sf the state object
     * @return the new position after parsing
     */
    private static int parse_number(SqliState sf) {
        int start = sf.pos;
        int pos = sf.pos;
        
        while (pos < sf.slen && ISDIGIT(sf.s.charAt(pos))) {
            pos += 1;
        }
        
        if (pos < sf.slen && sf.s.charAt(pos) == '.') {
            pos += 1;
            while (pos < sf.slen && ISDIGIT(sf.s.charAt(pos))) {
                pos += 1;
            }
        }
        
        st_assign(sf.current, TYPE_NUMBER, start, pos - start, sf.s.substring(start, pos));
        return pos;
    }
    
    /**
     * Parses a word token (keyword or bareword).
     * 
     * @param sf the state object
     * @return the new position after parsing
     */
    private static int parse_word(SqliState sf) {
        int pos = sf.pos;
        int wlen = strlencspn(sf.s, pos, sf.slen - pos, " []{}()<>:\\?=@!#~+-*/&|^%(),'\t\n\u000B\f\r\"\u00A0\u0000;");
        
        st_assign(sf.current, TYPE_BAREWORD, pos, wlen, sf.s.substring(pos, pos + wlen));
        
        if (wlen < LIBINJECTION_SQLI_TOKEN_SIZE) {
            String tokenVal = new String(sf.current.val, 0, wlen);
            char ch = libinjection_sqli_lookup_word(sf, LOOKUP_WORD, tokenVal, wlen);
            if (ch == CHAR_NULL) {
                ch = TYPE_BAREWORD;
            }
            sf.current.type = ch;
        }
        
        return pos + wlen;
    }
    
    /**
     * Looks up a word in the keyword dictionary.
     * 
     * @param sql_state the state object
     * @param lookup_type the type of lookup
     * @param str the word to look up
     * @param len the length of the word
     * @return the token type character, or '\0' if not found
     */
    private static char libinjection_sqli_lookup_word(SqliState sql_state, int lookup_type, String str, int len) {
        if (lookup_type == LOOKUP_FINGERPRINT) {
            return libinjection_sqli_check_fingerprint(sql_state) ? 'X' : '\0';
        } else {
            return bsearch_keyword_type(str, len, SqliKeywords.SQL_KEYWORDS);
        }
    }
    
    /**
     * Assigns values to a token.
     * 
     * @param st the token
     * @param stype the token type
     * @param pos the position
     * @param len the length
     * @param value the token value
     */
    private static void st_assign(SqliToken st, char stype, int pos, int len, String value) {
        int last = Math.min(len, LIBINJECTION_SQLI_TOKEN_SIZE - 1);
        st.type = stype;
        st.pos = pos;
        st.len = last;
        for (int i = 0; i < last && i < value.length(); i++) {
            st.val[i] = value.charAt(i);
        }
        st.val[last] = CHAR_NULL;
    }
    
    /**
     * Assigns a single character value to a token.
     * 
     * @param st the token
     * @param stype the token type
     * @param pos the position
     * @param len the length
     * @param value the character value
     */
    private static void st_assign_char(SqliToken st, char stype, int pos, int len, char value) {
        st.type = stype;
        st.pos = pos;
        st.len = 1;
        st.val[0] = value;
        st.val[1] = CHAR_NULL;
    }
    
    /**
     * Checks if a token is a unary operator.
     * 
     * @param st the token
     * @return true if the token is a unary operator
     */
    private static boolean st_is_unary_op(SqliToken st) {
        if (st.type != TYPE_OPERATOR) {
            return false;
        }
        
        int len = st.len;
        if (len == 1) {
            char ch = st.val[0];
            return ch == '+' || ch == '-' || ch == '!' || ch == '~';
        } else if (len == 2) {
            return st.val[0] == '!' && st.val[1] == '!';
        } else if (len == 3) {
            return cstrcasecmp("NOT", new String(st.val, 0, 3), 3) == 0;
        }
        return false;
    }
}