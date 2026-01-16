package com.cloud.apim.libinjection.impl;

/**
 * SQL injection detection implementation.
 * <p>
 * This class provides methods to detect SQL injection attacks by tokenizing
 * SQL input and generating fingerprints that are matched against known
 * malicious patterns. It supports both ANSI SQL and MySQL dialects.
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

    /**
     * Converts a fingerprint char array to a String, excluding null characters.
     * This is more efficient than new String(fp).replace("\0", "") which creates two String objects.
     */
    private static String fingerprintToString(char[] fp) {
        int len = 0;
        for (char c : fp) {
            if (c != '\0') len++;
            else break; // Fingerprints are null-terminated, so we can stop at first null
        }
        if (len == 0) return "";
        return new String(fp, 0, len);
    }

    private static int memchr2(String haystack, int offset, int len, char c0, char c1) {
        if (len < 2) {
            return -1;
        }
        int last = offset + len - 1;
        for (int i = offset; i < last; i++) {
            if (i + 1 < haystack.length() && haystack.charAt(i) == c0 && haystack.charAt(i + 1) == c1) {
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
                    if (i + j >= haystack.length() || haystack.charAt(i + j) != needle.charAt(j)) {
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
            if (offset + i >= s.length()) {
                return i;
            }
            if (accept.indexOf(s.charAt(offset + i)) == -1) {
                return i;
            }
        }
        return len;
    }

    private static int strlencspn(String s, int offset, int len, String reject) {
        for (int i = 0; i < len; i++) {
            if (offset + i >= s.length()) {
                return i;
            }
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
        for (int i = 0; i < n; i++) {
            char ca = i < a.length() ? a.charAt(i) : '\0';
            char cb = i < b.length() ? b.charAt(i) : '\0';
            if (cb >= 'a' && cb <= 'z') {
                cb = (char) (cb - 0x20);
            }
            if (ca >= 'a' && ca <= 'z') {
                ca = (char) (ca - 0x20);
            }
            if (ca != cb) {
                return ca - cb;
            } else if (ca == '\0') {
                return 0;
            }
        }
        return (a.length() <= n) ? 0 : 1;
    }

    private static boolean streq(String a, String b) {
        return a.equals(b);
    }

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

    private static char is_keyword(String key, int len) {
        return bsearch_keyword_type(key, len, SqliKeywords.SQL_KEYWORDS);
    }

    public static boolean libinjection_is_sqli(String input) {
        if (input == null || input.length() == 0) {
            return false;
        }

        SqliState sql_state = new SqliState();
        libinjection_sqli_init(sql_state, input, input.length(), 0);
        return libinjection_is_sqli(sql_state);
    }

    /**
     * Checks if the input is SQLi and returns the fingerprint.
     *
     * @param input the input string to analyze
     * @return a SqliResult containing the detection result and fingerprint
     */
    public static SqliResult libinjection_sqli(String input) {
        if (input == null || input.length() == 0) {
            return new SqliResult(false, "");
        }

        SqliState sql_state = new SqliState();
        libinjection_sqli_init(sql_state, input, input.length(), 0);
        boolean result = libinjection_is_sqli(sql_state);
        String fingerprint = fingerprintToString(sql_state.fingerprint);
        return new SqliResult(result, fingerprint);
    }

    /**
     * Initializes a SqliState for manual tokenization/folding.
     *
     * @param state the state to initialize
     * @param input the input string
     * @param flags the parsing flags
     */
    public static void sqli_init(SqliState state, String input, int flags) {
        libinjection_sqli_init(state, input, input.length(), flags);
    }

    /**
     * Performs token folding on the state.
     *
     * @param state the initialized state
     * @return the number of tokens after folding
     */
    public static int sqli_fold(SqliState state) {
        return libinjection_sqli_fold(state);
    }

    /**
     * Tokenizes the next token from the input.
     *
     * @param state the initialized state
     * @return true if a token was extracted, false if end of input
     */
    public static boolean sqli_tokenize(SqliState state) {
        return libinjection_sqli_tokenize(state);
    }

    /**
     * Result of SQLi detection containing the detection result and fingerprint.
     */
    public static class SqliResult {
        public final boolean isSqli;
        public final String fingerprint;

        public SqliResult(boolean isSqli, String fingerprint) {
            this.isSqli = isSqli;
            this.fingerprint = fingerprint;
        }
    }

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
        for (int i = 0; i < sf.tokenvec.length; i++) {
            sf.tokenvec[i].clear();
        }
    }

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

        // Single-pass quote detection instead of two separate indexOf calls
        boolean hasSingleQuote = false;
        boolean hasDoubleQuote = false;
        for (int i = 0; i < slen; i++) {
            char c = s.charAt(i);
            if (c == CHAR_SINGLE) {
                hasSingleQuote = true;
                if (hasDoubleQuote) break; // Found both, no need to continue
            } else if (c == CHAR_DOUBLE) {
                hasDoubleQuote = true;
                if (hasSingleQuote) break; // Found both, no need to continue
            }
        }

        if (hasSingleQuote) {
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

        if (hasDoubleQuote) {
            libinjection_sqli_fingerprint(sql_state, FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL);
            if (libinjection_sqli_check_fingerprint(sql_state)) {
                return true;
            }
        }

        return false;
    }

    private static boolean reparse_as_mysql(SqliState sql_state) {
        return sql_state.stats_comment_ddx > 0 || sql_state.stats_comment_hash > 0;
    }

    private static void libinjection_sqli_fingerprint(SqliState sql_state, int flags) {
        libinjection_sqli_reset(sql_state, flags);
        int tlen = libinjection_sqli_fold(sql_state);

        if (tlen > 2 &&
            sql_state.tokenvec[tlen - 1].type == TYPE_BAREWORD &&
            sql_state.tokenvec[tlen - 1].str_open == CHAR_TICK &&
            sql_state.tokenvec[tlen - 1].len == 0 &&
            sql_state.tokenvec[tlen - 1].str_close == CHAR_NULL) {
            sql_state.tokenvec[tlen - 1].type = TYPE_COMMENT;
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

    private static void libinjection_sqli_reset(SqliState sf, int flags) {
        if (flags == 0) {
            flags = FLAG_QUOTE_NONE | FLAG_SQL_ANSI;
        }
        String s = sf.s;
        int slen = sf.slen;
        libinjection_sqli_init(sf, s, slen, flags);
    }

    private static boolean libinjection_sqli_check_fingerprint(SqliState sql_state) {
        return libinjection_sqli_blacklist(sql_state) &&
               libinjection_sqli_not_whitelist(sql_state);
    }

    private static boolean libinjection_sqli_blacklist(SqliState sql_state) {
        char[] fp2 = new char[8];
        String fpStr = fingerprintToString(sql_state.fingerprint);
        int len = fpStr.length();

        if (len < 1) {
            return false;
        }

        fp2[0] = '0';
        for (int i = 0; i < len; ++i) {
            char ch = fpStr.charAt(i);
            if (ch >= 'a' && ch <= 'z') {
                ch = (char) (ch - 0x20);
            }
            fp2[i + 1] = ch;
        }
        fp2[len + 1] = '\0';

        String fp2Str = new String(fp2, 0, len + 1);
        return is_keyword(fp2Str, len + 1) == TYPE_FINGERPRINT;
    }

    private static boolean libinjection_sqli_not_whitelist(SqliState sql_state) {
        String fpStr = fingerprintToString(sql_state.fingerprint);
        int tlen = fpStr.length();

        if (tlen > 1 && sql_state.fingerprint[tlen - 1] == TYPE_COMMENT) {
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
                    String tokenVal = new String(sql_state.tokenvec[1].val, 0,
                            Math.min(sql_state.tokenvec[1].len, sql_state.tokenvec[1].val.length));
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

    private static boolean syntax_merge_words(SqliState sf, SqliToken a, SqliToken b) {
        if (!(a.type == TYPE_KEYWORD || a.type == TYPE_BAREWORD ||
              a.type == TYPE_OPERATOR || a.type == TYPE_UNION ||
              a.type == TYPE_FUNCTION || a.type == TYPE_EXPRESSION ||
              a.type == TYPE_TSQL || a.type == TYPE_SQLTYPE)) {
            return false;
        }

        if (!(b.type == TYPE_KEYWORD || b.type == TYPE_BAREWORD ||
              b.type == TYPE_OPERATOR || b.type == TYPE_UNION ||
              b.type == TYPE_FUNCTION || b.type == TYPE_EXPRESSION ||
              b.type == TYPE_TSQL || b.type == TYPE_SQLTYPE ||
              b.type == TYPE_LOGIC_OPERATOR)) {
            return false;
        }

        int sz1 = a.len;
        int sz2 = b.len;
        int sz3 = sz1 + sz2 + 1;
        if (sz3 >= LIBINJECTION_SQLI_TOKEN_SIZE) {
            return false;
        }

        char[] tmp = new char[LIBINJECTION_SQLI_TOKEN_SIZE];
        for (int i = 0; i < sz1 && i < a.val.length; i++) {
            tmp[i] = a.val[i];
        }
        tmp[sz1] = ' ';
        for (int i = 0; i < sz2 && i < b.val.length; i++) {
            tmp[sz1 + 1 + i] = b.val[i];
        }
        tmp[sz3] = CHAR_NULL;

        String tmpStr = new String(tmp, 0, sz3);
        char ch = libinjection_sqli_lookup_word(sf, LOOKUP_WORD, tmpStr, sz3);

        if (ch != CHAR_NULL) {
            st_assign(a, ch, a.pos, sz3, tmpStr);
            return true;
        } else {
            return false;
        }
    }

    private static int libinjection_sqli_fold(SqliState sf) {
        SqliToken last_comment = new SqliToken();
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
            if (pos >= LIBINJECTION_SQLI_MAX_TOKENS) {
                if ((sf.tokenvec[0].type == TYPE_NUMBER &&
                     (sf.tokenvec[1].type == TYPE_OPERATOR || sf.tokenvec[1].type == TYPE_COMMA) &&
                     sf.tokenvec[2].type == TYPE_LEFTPARENS &&
                     sf.tokenvec[3].type == TYPE_NUMBER &&
                     sf.tokenvec[4].type == TYPE_RIGHTPARENS) ||
                    (sf.tokenvec[0].type == TYPE_BAREWORD &&
                     sf.tokenvec[1].type == TYPE_OPERATOR &&
                     sf.tokenvec[2].type == TYPE_LEFTPARENS &&
                     (sf.tokenvec[3].type == TYPE_BAREWORD || sf.tokenvec[3].type == TYPE_NUMBER) &&
                     sf.tokenvec[4].type == TYPE_RIGHTPARENS) ||
                    (sf.tokenvec[0].type == TYPE_NUMBER &&
                     sf.tokenvec[1].type == TYPE_RIGHTPARENS &&
                     sf.tokenvec[2].type == TYPE_COMMA &&
                     sf.tokenvec[3].type == TYPE_LEFTPARENS &&
                     sf.tokenvec[4].type == TYPE_NUMBER) ||
                    (sf.tokenvec[0].type == TYPE_BAREWORD &&
                     sf.tokenvec[1].type == TYPE_RIGHTPARENS &&
                     sf.tokenvec[2].type == TYPE_OPERATOR &&
                     sf.tokenvec[3].type == TYPE_LEFTPARENS &&
                     sf.tokenvec[4].type == TYPE_BAREWORD)) {
                    if (pos > LIBINJECTION_SQLI_MAX_TOKENS) {
                        sf.tokenvec[1].copy(sf.tokenvec[LIBINJECTION_SQLI_MAX_TOKENS]);
                        pos = 2;
                        left = 0;
                    } else {
                        pos = 1;
                        left = 0;
                    }
                }
            }

            if (!more || left >= LIBINJECTION_SQLI_MAX_TOKENS) {
                left = pos;
                break;
            }

            while (more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && (pos - left) < 2) {
                sf.current = sf.tokenvec[pos];
                more = libinjection_sqli_tokenize(sf);
                if (more) {
                    if (sf.current.type == TYPE_COMMENT) {
                        last_comment.copy(sf.current);
                    } else {
                        last_comment.type = CHAR_NULL;
                        pos += 1;
                    }
                }
            }

            if (pos - left < 2) {
                left = pos;
                continue;
            }

            if (sf.tokenvec[left].type == TYPE_STRING &&
                sf.tokenvec[left + 1].type == TYPE_STRING) {
                pos -= 1;
                sf.stats_folds += 1;
                continue;
            } else if (sf.tokenvec[left].type == TYPE_SEMICOLON &&
                       sf.tokenvec[left + 1].type == TYPE_SEMICOLON) {
                pos -= 1;
                sf.stats_folds += 1;
                continue;
            } else if ((sf.tokenvec[left].type == TYPE_OPERATOR ||
                        sf.tokenvec[left].type == TYPE_LOGIC_OPERATOR) &&
                       (st_is_unary_op(sf.tokenvec[left + 1]) ||
                        sf.tokenvec[left + 1].type == TYPE_SQLTYPE)) {
                pos -= 1;
                sf.stats_folds += 1;
                left = 0;
                continue;
            } else if (sf.tokenvec[left].type == TYPE_LEFTPARENS &&
                       st_is_unary_op(sf.tokenvec[left + 1])) {
                pos -= 1;
                sf.stats_folds += 1;
                if (left > 0) {
                    left -= 1;
                }
                continue;
            } else if (syntax_merge_words(sf, sf.tokenvec[left], sf.tokenvec[left + 1])) {
                pos -= 1;
                sf.stats_folds += 1;
                if (left > 0) {
                    left -= 1;
                }
                continue;
            } else if (sf.tokenvec[left].type == TYPE_SEMICOLON &&
                       sf.tokenvec[left + 1].type == TYPE_FUNCTION &&
                       sf.tokenvec[left + 1].len >= 2 &&
                       (sf.tokenvec[left + 1].val[0] == 'I' || sf.tokenvec[left + 1].val[0] == 'i') &&
                       (sf.tokenvec[left + 1].val[1] == 'F' || sf.tokenvec[left + 1].val[1] == 'f')) {
                sf.tokenvec[left + 1].type = TYPE_TSQL;
                continue;
            } else if ((sf.tokenvec[left].type == TYPE_BAREWORD ||
                        sf.tokenvec[left].type == TYPE_VARIABLE) &&
                       sf.tokenvec[left + 1].type == TYPE_LEFTPARENS) {
                String val = new String(sf.tokenvec[left].val, 0, sf.tokenvec[left].len);
                if (cstrcasecmp("USER_ID", val, sf.tokenvec[left].len) == 0 ||
                    cstrcasecmp("USER_NAME", val, sf.tokenvec[left].len) == 0 ||
                    cstrcasecmp("DATABASE", val, sf.tokenvec[left].len) == 0 ||
                    cstrcasecmp("PASSWORD", val, sf.tokenvec[left].len) == 0 ||
                    cstrcasecmp("USER", val, sf.tokenvec[left].len) == 0 ||
                    cstrcasecmp("CURRENT_USER", val, sf.tokenvec[left].len) == 0 ||
                    cstrcasecmp("CURRENT_DATE", val, sf.tokenvec[left].len) == 0 ||
                    cstrcasecmp("CURRENT_TIME", val, sf.tokenvec[left].len) == 0 ||
                    cstrcasecmp("CURRENT_TIMESTAMP", val, sf.tokenvec[left].len) == 0 ||
                    cstrcasecmp("LOCALTIME", val, sf.tokenvec[left].len) == 0 ||
                    cstrcasecmp("LOCALTIMESTAMP", val, sf.tokenvec[left].len) == 0) {
                    sf.tokenvec[left].type = TYPE_FUNCTION;
                    continue;
                }
            } else if (sf.tokenvec[left].type == TYPE_KEYWORD) {
                String val = new String(sf.tokenvec[left].val, 0, sf.tokenvec[left].len);
                if (cstrcasecmp("IN", val, sf.tokenvec[left].len) == 0 ||
                    cstrcasecmp("NOT IN", val, sf.tokenvec[left].len) == 0) {
                    if (sf.tokenvec[left + 1].type == TYPE_LEFTPARENS) {
                        sf.tokenvec[left].type = TYPE_OPERATOR;
                    } else {
                        sf.tokenvec[left].type = TYPE_BAREWORD;
                    }
                    continue;
                }
            } else if (sf.tokenvec[left].type == TYPE_OPERATOR) {
                String val = new String(sf.tokenvec[left].val, 0, sf.tokenvec[left].len);
                if (cstrcasecmp("LIKE", val, sf.tokenvec[left].len) == 0 ||
                    cstrcasecmp("NOT LIKE", val, sf.tokenvec[left].len) == 0) {
                    if (sf.tokenvec[left + 1].type == TYPE_LEFTPARENS) {
                        sf.tokenvec[left].type = TYPE_FUNCTION;
                    }
                }
            } else if (sf.tokenvec[left].type == TYPE_SQLTYPE &&
                       (sf.tokenvec[left + 1].type == TYPE_BAREWORD ||
                        sf.tokenvec[left + 1].type == TYPE_NUMBER ||
                        sf.tokenvec[left + 1].type == TYPE_SQLTYPE ||
                        sf.tokenvec[left + 1].type == TYPE_LEFTPARENS ||
                        sf.tokenvec[left + 1].type == TYPE_FUNCTION ||
                        sf.tokenvec[left + 1].type == TYPE_VARIABLE ||
                        sf.tokenvec[left + 1].type == TYPE_STRING)) {
                sf.tokenvec[left].copy(sf.tokenvec[left + 1]);
                pos -= 1;
                sf.stats_folds += 1;
                left = 0;
                continue;
            } else if (sf.tokenvec[left].type == TYPE_COLLATE &&
                       sf.tokenvec[left + 1].type == TYPE_BAREWORD) {
                String val = new String(sf.tokenvec[left + 1].val, 0, sf.tokenvec[left + 1].len);
                if (val.indexOf('_') != -1) {
                    sf.tokenvec[left + 1].type = TYPE_SQLTYPE;
                    left = 0;
                }
            } else if (sf.tokenvec[left].type == TYPE_BACKSLASH) {
                if (st_is_arithmetic_op(sf.tokenvec[left + 1])) {
                    sf.tokenvec[left].type = TYPE_NUMBER;
                } else {
                    sf.tokenvec[left].copy(sf.tokenvec[left + 1]);
                    pos -= 1;
                    sf.stats_folds += 1;
                }
                left = 0;
                continue;
            } else if (sf.tokenvec[left].type == TYPE_LEFTPARENS &&
                       sf.tokenvec[left + 1].type == TYPE_LEFTPARENS) {
                pos -= 1;
                left = 0;
                sf.stats_folds += 1;
                continue;
            } else if (sf.tokenvec[left].type == TYPE_RIGHTPARENS &&
                       sf.tokenvec[left + 1].type == TYPE_RIGHTPARENS) {
                pos -= 1;
                left = 0;
                sf.stats_folds += 1;
                continue;
            } else if (sf.tokenvec[left].type == TYPE_LEFTBRACE &&
                       sf.tokenvec[left + 1].type == TYPE_BAREWORD) {
                if (sf.tokenvec[left + 1].len == 0) {
                    sf.tokenvec[left + 1].type = TYPE_EVIL;
                    return left + 2;
                }
                left = 0;
                pos -= 2;
                sf.stats_folds += 2;
                continue;
            } else if (sf.tokenvec[left + 1].type == TYPE_RIGHTBRACE) {
                pos -= 1;
                left = 0;
                sf.stats_folds += 1;
                continue;
            }

            while (more && pos <= LIBINJECTION_SQLI_MAX_TOKENS && pos - left < 3) {
                sf.current = sf.tokenvec[pos];
                more = libinjection_sqli_tokenize(sf);
                if (more) {
                    if (sf.current.type == TYPE_COMMENT) {
                        last_comment.copy(sf.current);
                    } else {
                        last_comment.type = CHAR_NULL;
                        pos += 1;
                    }
                }
            }

            if (pos - left < 3) {
                left = pos;
                continue;
            }

            if (sf.tokenvec[left].type == TYPE_NUMBER &&
                sf.tokenvec[left + 1].type == TYPE_OPERATOR &&
                sf.tokenvec[left + 2].type == TYPE_NUMBER) {
                pos -= 2;
                left = 0;
                continue;
            } else if (sf.tokenvec[left].type == TYPE_OPERATOR &&
                       sf.tokenvec[left + 1].type != TYPE_LEFTPARENS &&
                       sf.tokenvec[left + 2].type == TYPE_OPERATOR) {
                left = 0;
                pos -= 2;
                continue;
            } else if (sf.tokenvec[left].type == TYPE_LOGIC_OPERATOR &&
                       sf.tokenvec[left + 2].type == TYPE_LOGIC_OPERATOR) {
                pos -= 2;
                left = 0;
                continue;
            } else if (sf.tokenvec[left].type == TYPE_VARIABLE &&
                       sf.tokenvec[left + 1].type == TYPE_OPERATOR &&
                       (sf.tokenvec[left + 2].type == TYPE_VARIABLE ||
                        sf.tokenvec[left + 2].type == TYPE_NUMBER ||
                        sf.tokenvec[left + 2].type == TYPE_BAREWORD)) {
                pos -= 2;
                left = 0;
                continue;
            } else if ((sf.tokenvec[left].type == TYPE_BAREWORD ||
                        sf.tokenvec[left].type == TYPE_NUMBER) &&
                       sf.tokenvec[left + 1].type == TYPE_OPERATOR &&
                       (sf.tokenvec[left + 2].type == TYPE_NUMBER ||
                        sf.tokenvec[left + 2].type == TYPE_BAREWORD)) {
                pos -= 2;
                left = 0;
                continue;
            } else if ((sf.tokenvec[left].type == TYPE_BAREWORD ||
                        sf.tokenvec[left].type == TYPE_NUMBER ||
                        sf.tokenvec[left].type == TYPE_VARIABLE ||
                        sf.tokenvec[left].type == TYPE_STRING) &&
                       sf.tokenvec[left + 1].type == TYPE_OPERATOR &&
                       sf.tokenvec[left + 1].len == 2 &&
                       sf.tokenvec[left + 1].val[0] == ':' && sf.tokenvec[left + 1].val[1] == ':' &&
                       sf.tokenvec[left + 2].type == TYPE_SQLTYPE) {
                pos -= 2;
                left = 0;
                sf.stats_folds += 2;
                continue;
            } else if ((sf.tokenvec[left].type == TYPE_BAREWORD ||
                        sf.tokenvec[left].type == TYPE_NUMBER ||
                        sf.tokenvec[left].type == TYPE_STRING ||
                        sf.tokenvec[left].type == TYPE_VARIABLE) &&
                       sf.tokenvec[left + 1].type == TYPE_COMMA &&
                       (sf.tokenvec[left + 2].type == TYPE_NUMBER ||
                        sf.tokenvec[left + 2].type == TYPE_BAREWORD ||
                        sf.tokenvec[left + 2].type == TYPE_STRING ||
                        sf.tokenvec[left + 2].type == TYPE_VARIABLE)) {
                pos -= 2;
                left = 0;
                continue;
            } else if ((sf.tokenvec[left].type == TYPE_EXPRESSION ||
                        sf.tokenvec[left].type == TYPE_GROUP ||
                        sf.tokenvec[left].type == TYPE_COMMA) &&
                       st_is_unary_op(sf.tokenvec[left + 1]) &&
                       sf.tokenvec[left + 2].type == TYPE_LEFTPARENS) {
                sf.tokenvec[left + 1].copy(sf.tokenvec[left + 2]);
                pos -= 1;
                left = 0;
                continue;
            } else if ((sf.tokenvec[left].type == TYPE_KEYWORD ||
                        sf.tokenvec[left].type == TYPE_EXPRESSION ||
                        sf.tokenvec[left].type == TYPE_GROUP) &&
                       st_is_unary_op(sf.tokenvec[left + 1]) &&
                       (sf.tokenvec[left + 2].type == TYPE_NUMBER ||
                        sf.tokenvec[left + 2].type == TYPE_BAREWORD ||
                        sf.tokenvec[left + 2].type == TYPE_VARIABLE ||
                        sf.tokenvec[left + 2].type == TYPE_STRING ||
                        sf.tokenvec[left + 2].type == TYPE_FUNCTION)) {
                sf.tokenvec[left + 1].copy(sf.tokenvec[left + 2]);
                pos -= 1;
                left = 0;
                continue;
            } else if (sf.tokenvec[left].type == TYPE_COMMA &&
                       st_is_unary_op(sf.tokenvec[left + 1]) &&
                       (sf.tokenvec[left + 2].type == TYPE_NUMBER ||
                        sf.tokenvec[left + 2].type == TYPE_BAREWORD ||
                        sf.tokenvec[left + 2].type == TYPE_VARIABLE ||
                        sf.tokenvec[left + 2].type == TYPE_STRING)) {
                sf.tokenvec[left + 1].copy(sf.tokenvec[left + 2]);
                left = 0;
                pos -= 3;
                continue;
            } else if (sf.tokenvec[left].type == TYPE_COMMA &&
                       st_is_unary_op(sf.tokenvec[left + 1]) &&
                       sf.tokenvec[left + 2].type == TYPE_FUNCTION) {
                sf.tokenvec[left + 1].copy(sf.tokenvec[left + 2]);
                pos -= 1;
                left = 0;
                continue;
            } else if ((sf.tokenvec[left].type == TYPE_BAREWORD) &&
                       (sf.tokenvec[left + 1].type == TYPE_DOT) &&
                       (sf.tokenvec[left + 2].type == TYPE_BAREWORD)) {
                pos -= 2;
                left = 0;
                continue;
            } else if ((sf.tokenvec[left].type == TYPE_EXPRESSION) &&
                       (sf.tokenvec[left + 1].type == TYPE_DOT) &&
                       (sf.tokenvec[left + 2].type == TYPE_BAREWORD)) {
                sf.tokenvec[left + 1].copy(sf.tokenvec[left + 2]);
                pos -= 1;
                left = 0;
                continue;
            } else if ((sf.tokenvec[left].type == TYPE_FUNCTION) &&
                       (sf.tokenvec[left + 1].type == TYPE_LEFTPARENS) &&
                       (sf.tokenvec[left + 2].type != TYPE_RIGHTPARENS)) {
                String val = new String(sf.tokenvec[left].val, 0, sf.tokenvec[left].len);
                if (cstrcasecmp("USER", val, sf.tokenvec[left].len) == 0) {
                    sf.tokenvec[left].type = TYPE_BAREWORD;
                }
            }

            left += 1;
        }

        if (left < LIBINJECTION_SQLI_MAX_TOKENS && last_comment.type == TYPE_COMMENT) {
            sf.tokenvec[left].copy(last_comment);
            left += 1;
        }

        if (left > LIBINJECTION_SQLI_MAX_TOKENS) {
            left = LIBINJECTION_SQLI_MAX_TOKENS;
        }

        return left;
    }

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

            switch (ch) {
                case '\'':
                case '"':
                    sf.pos = parse_string(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '-':
                    sf.pos = parse_dash(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '#':
                    sf.pos = parse_hash(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '/':
                    sf.pos = parse_slash(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '\\':
                    sf.pos = parse_backslash(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '@':
                    sf.pos = parse_var(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '`':
                    sf.pos = parse_tick(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '$':
                    sf.pos = parse_money(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '[':
                    sf.pos = parse_bword(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '(':
                case ')':
                case ',':
                case ';':
                case '{':
                case '}':
                    sf.pos = parse_char(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '!':
                case '<':
                case '>':
                case '=':
                case '&':
                case '|':
                case ':':
                case '*':
                    sf.pos = parse_operator2(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '+':
                case '%':
                case '^':
                case '~':
                    sf.pos = parse_operator1(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '?':
                case ']':
                    sf.pos = parse_other(sf);
                    sf.stats_tokens += 1;
                    return true;

                case '.':
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    sf.pos = parse_number(sf);
                    // Check if a token was actually assigned (handles 1E, 1.e without exponent)
                    if (sf.current.type != TYPE_NONE) {
                        sf.stats_tokens += 1;
                        return true;
                    }
                    // No token assigned, continue parsing
                    continue;

                case 'B':
                case 'b':
                    sf.pos = parse_bstring(sf);
                    sf.stats_tokens += 1;
                    return true;

                case 'E':
                case 'e':
                    sf.pos = parse_estring(sf);
                    sf.stats_tokens += 1;
                    return true;

                case 'N':
                case 'n':
                    sf.pos = parse_nqstring(sf);
                    sf.stats_tokens += 1;
                    return true;

                case 'Q':
                case 'q':
                    sf.pos = parse_qstring(sf);
                    sf.stats_tokens += 1;
                    return true;

                case 'U':
                case 'u':
                    sf.pos = parse_ustring(sf);
                    sf.stats_tokens += 1;
                    return true;

                case 'X':
                case 'x':
                    sf.pos = parse_xstring(sf);
                    sf.stats_tokens += 1;
                    return true;

                default:
                    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_') {
                        sf.pos = parse_word(sf);
                    } else {
                        sf.pos = parse_word(sf);
                    }
                    sf.stats_tokens += 1;
                    return true;
            }
        }

        return false;
    }

    private static int parse_char(SqliState sf) {
        char ch = sf.s.charAt(sf.pos);
        st_assign_char(sf.current, ch, sf.pos, 1, ch);
        return sf.pos + 1;
    }

    private static int parse_operator1(SqliState sf) {
        char ch = sf.s.charAt(sf.pos);
        st_assign_char(sf.current, TYPE_OPERATOR, sf.pos, 1, ch);
        return sf.pos + 1;
    }

    private static int parse_other(SqliState sf) {
        char ch = sf.s.charAt(sf.pos);
        st_assign_char(sf.current, TYPE_UNKNOWN, sf.pos, 1, ch);
        return sf.pos + 1;
    }

    private static int parse_operator2(SqliState sf) {
        String cs = sf.s;
        int slen = sf.slen;
        int pos = sf.pos;

        if (pos + 1 >= slen) {
            return parse_operator1(sf);
        }

        if (pos + 2 < slen && cs.charAt(pos) == '<' && cs.charAt(pos + 1) == '=' && cs.charAt(pos + 2) == '>') {
            st_assign(sf.current, TYPE_OPERATOR, pos, 3, cs.substring(pos, pos + 3));
            return pos + 3;
        }

        String twoChar = cs.substring(pos, pos + 2);
        char ch = libinjection_sqli_lookup_word(sf, LOOKUP_OPERATOR, twoChar, 2);
        if (ch != CHAR_NULL) {
            st_assign(sf.current, ch, pos, 2, twoChar);
            return pos + 2;
        }

        if (cs.charAt(pos) == ':') {
            st_assign(sf.current, TYPE_COLON, pos, 1, cs.substring(pos, pos + 1));
            return pos + 1;
        }

        return parse_operator1(sf);
    }

    private static int parse_hash(SqliState sf) {
        sf.stats_comment_hash += 1;
        if ((sf.flags & FLAG_SQL_MYSQL) != 0) {
            sf.stats_comment_hash += 1;
            return parse_eol_comment(sf);
        } else {
            st_assign_char(sf.current, TYPE_OPERATOR, sf.pos, 1, '#');
            return sf.pos + 1;
        }
    }

    private static int parse_dash(SqliState sf) {
        String cs = sf.s;
        int slen = sf.slen;
        int pos = sf.pos;

        if (pos + 2 < slen && cs.charAt(pos + 1) == '-' && char_is_white(cs.charAt(pos + 2))) {
            sf.stats_comment_ddw += 1;
            return parse_eol_comment(sf);
        } else if (pos + 2 == slen && cs.charAt(pos + 1) == '-') {
            sf.stats_comment_ddw += 1;
            return parse_eol_comment(sf);
        } else if (pos + 1 < slen && cs.charAt(pos + 1) == '-' && (sf.flags & FLAG_SQL_ANSI) != 0) {
            sf.stats_comment_ddx += 1;
            return parse_eol_comment(sf);
        } else {
            st_assign_char(sf.current, TYPE_OPERATOR, pos, 1, '-');
            return pos + 1;
        }
    }

    private static int parse_slash(SqliState sf) {
        String cs = sf.s;
        int slen = sf.slen;
        int pos = sf.pos;
        char ctype = TYPE_COMMENT;

        if (pos + 1 >= slen || cs.charAt(pos + 1) != '*') {
            return parse_operator1(sf);
        }

        int endpos = memchr2(cs, pos + 2, slen - pos - 2, '*', '/');
        int clen;
        if (endpos == -1) {
            clen = slen - pos;
        } else {
            clen = endpos - pos + 2;
        }

        if (endpos != -1 && memchr2(cs, pos + 2, endpos - pos - 1, '/', '*') != -1) {
            ctype = TYPE_EVIL;
        } else if (is_mysql_comment(cs, slen, pos)) {
            ctype = TYPE_EVIL;
        }

        st_assign(sf.current, ctype, pos, clen, cs.substring(pos, Math.min(pos + clen, slen)));
        sf.stats_comment_c += 1;
        return pos + clen;
    }

    private static boolean is_mysql_comment(String cs, int len, int pos) {
        if (pos + 2 >= len) {
            return false;
        }
        return cs.charAt(pos + 2) == '!';
    }

    private static int parse_backslash(SqliState sf) {
        String cs = sf.s;
        int slen = sf.slen;
        int pos = sf.pos;

        if (pos + 1 < slen && cs.charAt(pos + 1) == 'N') {
            st_assign(sf.current, TYPE_NUMBER, pos, 2, cs.substring(pos, pos + 2));
            return pos + 2;
        } else {
            st_assign_char(sf.current, TYPE_BACKSLASH, pos, 1, cs.charAt(pos));
            return pos + 1;
        }
    }

    private static int parse_var(SqliState sf) {
        String cs = sf.s;
        int slen = sf.slen;
        int pos = sf.pos + 1;

        if (pos < slen && cs.charAt(pos) == '@') {
            pos += 1;
            sf.current.count = 2;
        } else {
            sf.current.count = 1;
        }

        if (pos < slen) {
            if (cs.charAt(pos) == '`') {
                sf.pos = pos;
                pos = parse_tick(sf);
                sf.current.type = TYPE_VARIABLE;
                return pos;
            } else if (cs.charAt(pos) == CHAR_SINGLE || cs.charAt(pos) == CHAR_DOUBLE) {
                sf.pos = pos;
                pos = parse_string(sf);
                sf.current.type = TYPE_VARIABLE;
                return pos;
            }
        }

        int xlen = strlencspn(cs, pos, slen - pos, " <>:\\?=@!#~+-*/&|^%(),';\t\n\u000B\f\r'`\"");
        if (xlen == 0) {
            st_assign(sf.current, TYPE_VARIABLE, pos, 0, "");
            return pos;
        } else {
            st_assign(sf.current, TYPE_VARIABLE, pos, xlen, cs.substring(pos, pos + xlen));
            return pos + xlen;
        }
    }

    private static int parse_money(SqliState sf) {
        String cs = sf.s;
        int slen = sf.slen;
        int pos = sf.pos;

        if (pos + 1 == slen) {
            st_assign_char(sf.current, TYPE_BAREWORD, pos, 1, '$');
            return slen;
        }

        int xlen = strlenspn(cs, pos + 1, slen - pos - 1, "0123456789.,");
        if (xlen == 0) {
            if (cs.charAt(pos + 1) == '$') {
                int strend = memchr2(cs, pos + 2, slen - pos - 2, '$', '$');
                if (strend == -1) {
                    st_assign(sf.current, TYPE_STRING, pos + 2, slen - (pos + 2), cs.substring(pos + 2));
                    sf.current.str_open = '$';
                    sf.current.str_close = CHAR_NULL;
                    return slen;
                } else {
                    st_assign(sf.current, TYPE_STRING, pos + 2, strend - (pos + 2), cs.substring(pos + 2, strend));
                    sf.current.str_open = '$';
                    sf.current.str_close = '$';
                    return strend + 2;
                }
            } else {
                int taglen = strlenspn(cs, pos + 1, slen - pos - 1, "abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
                if (taglen == 0) {
                    st_assign_char(sf.current, TYPE_BAREWORD, pos, 1, '$');
                    return pos + 1;
                }
                if (pos + taglen + 1 >= slen || cs.charAt(pos + taglen + 1) != '$') {
                    st_assign_char(sf.current, TYPE_BAREWORD, pos, 1, '$');
                    return pos + 1;
                }

                String tag = cs.substring(pos, pos + taglen + 2);
                int strend = my_memmem(cs, pos + taglen + 2, slen - (pos + taglen + 2), tag);

                if (strend == -1) {
                    st_assign(sf.current, TYPE_STRING, pos + taglen + 2, slen - pos - taglen - 2, cs.substring(pos + taglen + 2));
                    sf.current.str_open = '$';
                    sf.current.str_close = CHAR_NULL;
                    return slen;
                } else {
                    st_assign(sf.current, TYPE_STRING, pos + taglen + 2, strend - (pos + taglen + 2), cs.substring(pos + taglen + 2, strend));
                    sf.current.str_open = '$';
                    sf.current.str_close = '$';
                    return strend + taglen + 2;
                }
            }
        } else if (xlen == 1 && cs.charAt(pos + 1) == '.') {
            return parse_word(sf);
        } else {
            st_assign(sf.current, TYPE_NUMBER, pos, 1 + xlen, cs.substring(pos, pos + 1 + xlen));
            return pos + 1 + xlen;
        }
    }

    private static int parse_tick(SqliState sf) {
        int pos = parse_string_core(sf.s, sf.slen, sf.pos, sf.current, CHAR_TICK, 1);

        char ch = libinjection_sqli_lookup_word(sf, LOOKUP_WORD, new String(sf.current.val, 0, sf.current.len), sf.current.len);
        if (ch == TYPE_FUNCTION) {
            sf.current.type = TYPE_FUNCTION;
        } else {
            sf.current.type = TYPE_BAREWORD;
        }
        return pos;
    }

    private static int parse_string(SqliState sf) {
        return parse_string_core(sf.s, sf.slen, sf.pos, sf.current, sf.s.charAt(sf.pos), 1);
    }

    private static int parse_estring(SqliState sf) {
        String cs = sf.s;
        int slen = sf.slen;
        int pos = sf.pos;

        if (pos + 2 >= slen || cs.charAt(pos + 1) != CHAR_SINGLE) {
            return parse_word(sf);
        }
        return parse_string_core(cs, slen, pos, sf.current, CHAR_SINGLE, 2);
    }

    private static int parse_ustring(SqliState sf) {
        String cs = sf.s;
        int slen = sf.slen;
        int pos = sf.pos;

        if (pos + 2 < slen && cs.charAt(pos + 1) == '&' && cs.charAt(pos + 2) == '\'') {
            sf.pos += 2;
            pos = parse_string(sf);
            sf.current.str_open = 'u';
            if (sf.current.str_close == '\'') {
                sf.current.str_close = 'u';
            }
            return pos;
        } else {
            return parse_word(sf);
        }
    }

    private static int parse_qstring_core(SqliState sf, int offset) {
        String cs = sf.s;
        int slen = sf.slen;
        int pos = sf.pos + offset;

        if (pos >= slen || (cs.charAt(pos) != 'q' && cs.charAt(pos) != 'Q') || pos + 2 >= slen || cs.charAt(pos + 1) != '\'') {
            return parse_word(sf);
        }

        char ch = cs.charAt(pos + 2);
        if (ch < 33) {
            return parse_word(sf);
        }

        switch (ch) {
            case '(':
                ch = ')';
                break;
            case '[':
                ch = ']';
                break;
            case '{':
                ch = '}';
                break;
            case '<':
                ch = '>';
                break;
        }

        int strend = memchr2(cs, pos + 3, slen - pos - 3, ch, '\'');
        if (strend == -1) {
            st_assign(sf.current, TYPE_STRING, pos + 3, slen - pos - 3, cs.substring(pos + 3));
            sf.current.str_open = 'q';
            sf.current.str_close = CHAR_NULL;
            return slen;
        } else {
            st_assign(sf.current, TYPE_STRING, pos + 3, strend - pos - 3, cs.substring(pos + 3, strend));
            sf.current.str_open = 'q';
            sf.current.str_close = 'q';
            return strend + 2;
        }
    }

    private static int parse_qstring(SqliState sf) {
        return parse_qstring_core(sf, 0);
    }

    private static int parse_nqstring(SqliState sf) {
        int slen = sf.slen;
        int pos = sf.pos;
        if (pos + 2 < slen && sf.s.charAt(pos + 1) == CHAR_SINGLE) {
            return parse_estring(sf);
        }
        return parse_qstring_core(sf, 1);
    }

    private static int parse_bstring(SqliState sf) {
        String cs = sf.s;
        int pos = sf.pos;
        int slen = sf.slen;

        if (pos + 2 >= slen || cs.charAt(pos + 1) != '\'') {
            return parse_word(sf);
        }

        int wlen = strlenspn(cs, pos + 2, slen - pos - 2, "01");
        if (pos + 2 + wlen >= slen || cs.charAt(pos + 2 + wlen) != '\'') {
            return parse_word(sf);
        }
        st_assign(sf.current, TYPE_NUMBER, pos, wlen + 3, cs.substring(pos, pos + wlen + 3));
        return pos + 2 + wlen + 1;
    }

    private static int parse_xstring(SqliState sf) {
        String cs = sf.s;
        int pos = sf.pos;
        int slen = sf.slen;

        if (pos + 2 >= slen || cs.charAt(pos + 1) != '\'') {
            return parse_word(sf);
        }

        int wlen = strlenspn(cs, pos + 2, slen - pos - 2, "0123456789ABCDEFabcdef");
        if (pos + 2 + wlen >= slen || cs.charAt(pos + 2 + wlen) != '\'') {
            return parse_word(sf);
        }
        st_assign(sf.current, TYPE_NUMBER, pos, wlen + 3, cs.substring(pos, pos + wlen + 3));
        return pos + 2 + wlen + 1;
    }

    private static int parse_bword(SqliState sf) {
        String cs = sf.s;
        int pos = sf.pos;
        int slen = sf.slen;

        int endpos = cs.indexOf(']', pos);
        if (endpos == -1 || endpos >= slen) {
            st_assign(sf.current, TYPE_BAREWORD, pos, slen - pos, cs.substring(pos));
            return slen;
        } else {
            st_assign(sf.current, TYPE_BAREWORD, pos, endpos - pos + 1, cs.substring(pos, endpos + 1));
            return endpos + 1;
        }
    }

    private static int parse_string_core(String cs, int len, int pos, SqliToken st, char delim, int offset) {
        int qpos = cs.indexOf(delim, pos + offset);

        if (offset > 0) {
            st.str_open = delim;
        } else {
            st.str_open = CHAR_NULL;
        }

        while (true) {
            if (qpos == -1 || qpos >= len) {
                st_assign(st, TYPE_STRING, pos + offset, len - pos - offset, cs.substring(pos + offset, len));
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

    private static boolean is_backslash_escaped(String s, int end, int start) {
        if (end < start || end < 0) {
            return false;
        }
        int count = 0;
        for (int ptr = end; ptr >= start; ptr--) {
            if (s.charAt(ptr) != '\\') {
                break;
            }
            count++;
        }
        return (count & 1) == 1;
    }

    private static boolean is_double_delim_escaped(String s, int cur, int end) {
        return (cur + 1) < end && s.charAt(cur + 1) == s.charAt(cur);
    }

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

    private static int parse_number(SqliState sf) {
        String cs = sf.s;
        int slen = sf.slen;
        int pos = sf.pos;
        String digits = null;
        boolean have_e = false;
        boolean have_exp = false;

        if (cs.charAt(pos) == '0' && pos + 1 < slen) {
            char c1 = cs.charAt(pos + 1);
            if (c1 == 'X' || c1 == 'x') {
                digits = "0123456789ABCDEFabcdef";
            } else if (c1 == 'B' || c1 == 'b') {
                digits = "01";
            }

            if (digits != null) {
                int xlen = strlenspn(cs, pos + 2, slen - pos - 2, digits);
                if (xlen == 0) {
                    st_assign(sf.current, TYPE_BAREWORD, pos, 2, cs.substring(pos, pos + 2));
                    return pos + 2;
                } else {
                    st_assign(sf.current, TYPE_NUMBER, pos, 2 + xlen, cs.substring(pos, pos + 2 + xlen));
                    return pos + 2 + xlen;
                }
            }
        }

        int start = pos;
        while (pos < slen && ISDIGIT(cs.charAt(pos))) {
            pos += 1;
        }

        if (pos < slen && cs.charAt(pos) == '.') {
            pos += 1;
            while (pos < slen && ISDIGIT(cs.charAt(pos))) {
                pos += 1;
            }
            if (pos - start == 1) {
                st_assign_char(sf.current, TYPE_DOT, start, 1, '.');
                return pos;
            }
        }

        if (pos < slen) {
            char chE = cs.charAt(pos);
            if (chE == 'E' || chE == 'e') {
                have_e = true;
                pos += 1;
                if (pos < slen && (cs.charAt(pos) == '+' || cs.charAt(pos) == '-')) {
                    pos += 1;
                }
                while (pos < slen && ISDIGIT(cs.charAt(pos))) {
                    have_exp = true;
                    pos += 1;
                }
            }
        }

        if (pos < slen) {
            char chS = cs.charAt(pos);
            if (chS == 'd' || chS == 'D' || chS == 'f' || chS == 'F') {
                if (pos + 1 == slen) {
                    pos += 1;
                } else if (char_is_white(cs.charAt(pos + 1)) || cs.charAt(pos + 1) == ';') {
                    pos += 1;
                } else if (cs.charAt(pos + 1) == 'u' || cs.charAt(pos + 1) == 'U') {
                    pos += 1;
                }
            }
        }

        if (!(have_e && !have_exp)) {
            st_assign(sf.current, TYPE_NUMBER, start, pos - start, cs.substring(start, pos));
        }

        return pos;
    }

    private static int parse_word(SqliState sf) {
        String cs = sf.s;
        int pos = sf.pos;
        int wlen = strlencspn(cs, pos, sf.slen - pos, " []{}()<>:\\?=@!#~+-*/&|^%(),'\t\n\u000B\f\r\"\u00A0\u0000;");

        st_assign(sf.current, TYPE_BAREWORD, pos, wlen, cs.substring(pos, pos + wlen));

        for (int i = 0; i < sf.current.len; ++i) {
            char delim = sf.current.val[i];
            if (delim == '.' || delim == '`') {
                String partial = new String(sf.current.val, 0, i);
                char ch = libinjection_sqli_lookup_word(sf, LOOKUP_WORD, partial, i);
                if (ch != TYPE_NONE && ch != TYPE_BAREWORD) {
                    sf.current.clear();
                    st_assign(sf.current, ch, pos, i, cs.substring(pos, pos + i));
                    return pos + i;
                }
            }
        }

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

    private static char libinjection_sqli_lookup_word(SqliState sql_state, int lookup_type, String str, int len) {
        if (lookup_type == LOOKUP_FINGERPRINT) {
            return libinjection_sqli_check_fingerprint(sql_state) ? 'X' : '\0';
        } else {
            return bsearch_keyword_type(str, len, SqliKeywords.SQL_KEYWORDS);
        }
    }

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

    private static void st_assign_char(SqliToken st, char stype, int pos, int len, char value) {
        st.type = stype;
        st.pos = pos;
        st.len = 1;
        st.val[0] = value;
        st.val[1] = CHAR_NULL;
    }

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

    private static boolean st_is_arithmetic_op(SqliToken st) {
        char ch = st.val[0];
        return st.type == TYPE_OPERATOR && st.len == 1 &&
               (ch == '*' || ch == '/' || ch == '-' || ch == '+' || ch == '%');
    }
}
