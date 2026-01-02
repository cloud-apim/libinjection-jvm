package com.cloud.apim.libinjection.impl;

/**
 * XSS (Cross-Site Scripting) detection implementation.
 * <p>
 * This class provides methods to detect XSS attacks by analyzing HTML content
 * for dangerous tags, attributes, and URL schemes that could be used to execute
 * malicious scripts. It uses the HTML5 parser to tokenize input and checks
 * against blacklists of known dangerous patterns.
 * </p>
 */
public class LibInjectionXSS {
    
    /**
     * Enumeration of attribute types for XSS detection.
     */
    private enum AttributeType {
        /** No special type - safe attribute. */
        TYPE_NONE,
        /** Blacklisted attribute - always dangerous. */
        TYPE_BLACK,
        /** Attribute containing a URL - needs URL validation. */
        TYPE_ATTR_URL,
        /** Style attribute - potentially dangerous. */
        TYPE_STYLE,
        /** Indirect attribute - value determines another attribute. */
        TYPE_ATTR_INDIRECT
    }
    
    /**
     * Helper class to associate attribute names with their types.
     */
    private static class StringType {
        String name;
        AttributeType atype;
        
        StringType(String name, AttributeType atype) {
            this.name = name;
            this.atype = atype;
        }
    }
    
    private static final int[] gsHexDecodeMap = new int[] {
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        0,   1,   2,   3,   4,   5,   6,   7,   8,   9, 256, 256,
        256, 256, 256, 256, 256,  10,  11,  12,  13,  14,  15, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256,  10,  11,  12,  13,  14,  15, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 256
    };
    
    private static final StringType[] BLACKATTR = new StringType[] {
        new StringType("ACTION", AttributeType.TYPE_ATTR_URL),
        new StringType("ATTRIBUTENAME", AttributeType.TYPE_ATTR_INDIRECT),
        new StringType("BY", AttributeType.TYPE_ATTR_URL),
        new StringType("BACKGROUND", AttributeType.TYPE_ATTR_URL),
        new StringType("DATAFORMATAS", AttributeType.TYPE_BLACK),
        new StringType("DATASRC", AttributeType.TYPE_BLACK),
        new StringType("DYNSRC", AttributeType.TYPE_ATTR_URL),
        new StringType("FILTER", AttributeType.TYPE_STYLE),
        new StringType("FORMACTION", AttributeType.TYPE_ATTR_URL),
        new StringType("FOLDER", AttributeType.TYPE_ATTR_URL),
        new StringType("FROM", AttributeType.TYPE_ATTR_URL),
        new StringType("HANDLER", AttributeType.TYPE_ATTR_URL),
        new StringType("HREF", AttributeType.TYPE_ATTR_URL),
        new StringType("LOWSRC", AttributeType.TYPE_ATTR_URL),
        new StringType("POSTER", AttributeType.TYPE_ATTR_URL),
        new StringType("SRC", AttributeType.TYPE_ATTR_URL),
        new StringType("STYLE", AttributeType.TYPE_STYLE),
        new StringType("TO", AttributeType.TYPE_ATTR_URL),
        new StringType("VALUES", AttributeType.TYPE_ATTR_URL),
        new StringType("XLINK:HREF", AttributeType.TYPE_ATTR_URL),
        new StringType(null, AttributeType.TYPE_NONE)
    };
    
    private static final String[] BLACKTAG = new String[] {
        "APPLET",
        "BASE",
        "COMMENT",
        "EMBED",
        "FRAME",
        "FRAMESET",
        "HANDLER",
        "IFRAME",
        "IMPORT",
        "ISINDEX",
        "LINK",
        "LISTENER",
        "META",
        "NOSCRIPT",
        "OBJECT",
        "SCRIPT",
        "STYLE",
        "VMLFRAME",
        "XML",
        "XSS",
        null
    };
    
    /**
     * Result of HTML entity decoding operation.
     */
    private static class HtmlDecodeResult {
        int value;
        int consumed;
        
        HtmlDecodeResult(int value, int consumed) {
            this.value = value;
            this.consumed = consumed;
        }
    }
    
    /**
     * Decodes an HTML entity at the specified position.
     * <p>
     * Handles numeric character references like &amp;#65; or &amp;#x41;
     * </p>
     * 
     * @param src the source string
     * @param len the length to consider
     * @param offset the offset to start decoding
     * @return the decoded result with value and consumed characters
     */
    private static HtmlDecodeResult html_decode_char_at(String src, int len, int offset) {
        int val = 0;
        int i;
        int ch;
        
        if (len == 0 || src == null || offset >= src.length()) {
            return new HtmlDecodeResult(-1, 0);
        }
        
        if (src.charAt(offset) != '&' || len < 2) {
            return new HtmlDecodeResult((int) src.charAt(offset), 1);
        }
        
        if (offset + 1 >= src.length() || src.charAt(offset + 1) != '#') {
            return new HtmlDecodeResult('&', 1);
        }
        
        if (offset + 2 < src.length() && (src.charAt(offset + 2) == 'x' || src.charAt(offset + 2) == 'X')) {
            if (offset + 3 >= src.length()) {
                return new HtmlDecodeResult('&', 1);
            }
            ch = (int) src.charAt(offset + 3);
            ch = gsHexDecodeMap[ch];
            if (ch == 256) {
                return new HtmlDecodeResult('&', 1);
            }
            val = ch;
            i = 4;
            while (offset + i < len && offset + i < src.length()) {
                ch = (int) src.charAt(offset + i);
                if (ch == ';') {
                    return new HtmlDecodeResult(val, i + 1);
                }
                ch = gsHexDecodeMap[ch];
                if (ch == 256) {
                    return new HtmlDecodeResult(val, i);
                }
                val = (val * 16) + ch;
                if (val > 0x1000FF) {
                    return new HtmlDecodeResult('&', 1);
                }
                ++i;
            }
            return new HtmlDecodeResult(val, i);
        } else {
            i = 2;
            if (offset + i >= src.length()) {
                return new HtmlDecodeResult('&', 1);
            }
            ch = (int) src.charAt(offset + i);
            if (ch < '0' || ch > '9') {
                return new HtmlDecodeResult('&', 1);
            }
            val = ch - '0';
            i += 1;
            while (offset + i < len && offset + i < src.length()) {
                ch = (int) src.charAt(offset + i);
                if (ch == ';') {
                    return new HtmlDecodeResult(val, i + 1);
                }
                if (ch < '0' || ch > '9') {
                    return new HtmlDecodeResult(val, i);
                }
                val = (val * 10) + (ch - '0');
                if (val > 0x1000FF) {
                    return new HtmlDecodeResult('&', 1);
                }
                ++i;
            }
            return new HtmlDecodeResult(val, i);
        }
    }
    
    /**
     * Case-insensitive string comparison that handles null characters.
     * 
     * @param a the first string
     * @param b the second string
     * @param n the maximum number of characters to compare
     * @return 0 if equal, non-zero otherwise
     */
    private static int cstrcasecmp_with_null(String a, String b, int n) {
        char ca;
        char cb;
        int aIdx = 0;
        int bIdx = 0;
        
        while (n-- > 0 && bIdx < b.length()) {
            cb = b.charAt(bIdx++);
            if (cb == '\0') continue;
            
            if (aIdx >= a.length()) {
                return 1;
            }
            ca = a.charAt(aIdx++);
            
            if (cb >= 'a' && cb <= 'z') {
                cb -= 0x20;
            }
            if (ca != cb) {
                return 1;
            }
        }
        
        if (aIdx == a.length()) {
            return 0;
        } else {
            return 1;
        }
    }
    
    /**
     * Checks if string b starts with string a, considering HTML encoding.
     * <p>
     * This method decodes HTML entities in b while comparing.
     * </p>
     * 
     * @param a the prefix to check for
     * @param b the string to check (may contain HTML entities)
     * @param n the maximum length to check in b
     * @return true if b starts with a (after decoding), false otherwise
     */
    private static boolean htmlencode_startswith(String a, String b, int n) {
        int bOffset = 0;
        int cb;
        boolean first = true;
        
        while (n > 0 && bOffset < b.length()) {
            if (a.isEmpty()) {
                return true;
            }
            HtmlDecodeResult result = html_decode_char_at(b, n, bOffset);
            cb = result.value;
            bOffset += result.consumed;
            n -= result.consumed;
            
            if (first && cb <= 32) {
                continue;
            }
            first = false;
            
            if (cb == 0) {
                continue;
            }
            
            if (cb == 10) {
                continue;
            }
            
            if (cb >= 'a' && cb <= 'z') {
                cb -= 0x20;
            }
            
            if (a.charAt(0) != (char) cb) {
                return false;
            }
            a = a.substring(1);
        }
        
        return a.isEmpty();
    }
    
    /**
     * Checks if the given tag name is blacklisted.
     * <p>
     * Blacklisted tags include script, iframe, object, embed, etc.
     * </p>
     * 
     * @param s the tag name to check
     * @param len the length of the tag name
     * @return true if the tag is blacklisted, false otherwise
     */
    private static boolean is_black_tag(String s, int len) {
        if (len < 3) {
            return false;
        }
        
        for (String black : BLACKTAG) {
            if (black == null) break;
            if (cstrcasecmp_with_null(black, s, len) == 0) {
                return true;
            }
        }
        
        if (len >= 3) {
            char c0 = s.charAt(0);
            char c1 = s.charAt(1);
            char c2 = s.charAt(2);
            if ((c0 == 's' || c0 == 'S') &&
                (c1 == 'v' || c1 == 'V') &&
                (c2 == 'g' || c2 == 'G')) {
                return true;
            }
            
            if ((c0 == 'x' || c0 == 'X') &&
                (c1 == 's' || c1 == 'S') &&
                (c2 == 'l' || c2 == 'L')) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Checks if the given attribute name is blacklisted and returns its type.
     * <p>
     * Blacklisted attributes include onclick, onload, href, src, etc.
     * </p>
     * 
     * @param s the attribute name to check
     * @param len the length of the attribute name
     * @return the attribute type (TYPE_NONE if safe)
     */
    private static AttributeType is_black_attr(String s, int len) {
        if (len < 2) {
            return AttributeType.TYPE_NONE;
        }
        
        if (len >= 5) {
            char c0 = s.charAt(0);
            char c1 = s.charAt(1);
            if ((c0 == 'o' || c0 == 'O') && (c1 == 'n' || c1 == 'N')) {
                return AttributeType.TYPE_BLACK;
            }
            
            if (cstrcasecmp_with_null("XMLNS", s, 5) == 0 || cstrcasecmp_with_null("XLINK", s, 5) == 0) {
                return AttributeType.TYPE_BLACK;
            }
        }
        
        for (StringType black : BLACKATTR) {
            if (black.name == null) break;
            if (cstrcasecmp_with_null(black.name, s, len) == 0) {
                return black.atype;
            }
        }
        
        return AttributeType.TYPE_NONE;
    }
    
    /**
     * Checks if the given URL contains a dangerous protocol.
     * <p>
     * Dangerous protocols include javascript:, data:, vbscript:, etc.
     * </p>
     * 
     * @param s the URL to check
     * @param len the length of the URL
     * @return true if the URL is dangerous, false otherwise
     */
    private static boolean is_black_url(String s, int len) {
        String data_url = "DATA";
        String viewsource_url = "VIEW-SOURCE";
        String vbscript_url = "VBSCRIPT";
        String javascript_url = "JAVA";
        
        int offset = 0;
        while (len > 0 && offset < s.length()) {
            char ch = s.charAt(offset);
            if (ch <= 32 || ch >= 127) {
                ++offset;
                --len;
            } else {
                break;
            }
        }
        
        String remaining = s.substring(offset);
        
        if (htmlencode_startswith(data_url, remaining, len)) {
            return true;
        }
        
        if (htmlencode_startswith(viewsource_url, remaining, len)) {
            return true;
        }
        
        if (htmlencode_startswith(javascript_url, remaining, len)) {
            return true;
        }
        
        if (htmlencode_startswith(vbscript_url, remaining, len)) {
            return true;
        }
        return false;
    }
    
    /**
     * Checks if the input contains XSS patterns in the given parsing context.
     * 
     * @param s the input string to analyze
     * @param len the length of the input
     * @param flags the HTML5 parsing context flags
     * @return true if XSS is detected, false otherwise
     */
    public static boolean libinjection_is_xss(String s, int len, Html5Flags flags) {
        H5State h5 = new H5State();
        AttributeType attr = AttributeType.TYPE_NONE;
        
        LibInjectionHTML5.libinjection_h5_init(h5, s, len, flags);
        while (LibInjectionHTML5.libinjection_h5_next(h5) != 0) {
            if (h5.token_type != Html5Type.ATTR_VALUE) {
                attr = AttributeType.TYPE_NONE;
            }
            
            if (h5.token_type == Html5Type.DOCTYPE) {
                return true;
            } else if (h5.token_type == Html5Type.TAG_NAME_OPEN) {
                if (is_black_tag(h5.token_start, h5.token_len)) {
                    return true;
                }
            } else if (h5.token_type == Html5Type.ATTR_NAME) {
                attr = is_black_attr(h5.token_start, h5.token_len);
            } else if (h5.token_type == Html5Type.ATTR_VALUE) {
                switch (attr) {
                    case TYPE_NONE:
                        break;
                    case TYPE_BLACK:
                        return true;
                    case TYPE_ATTR_URL:
                        if (is_black_url(h5.token_start, h5.token_len)) {
                            return true;
                        }
                        break;
                    case TYPE_STYLE:
                        return true;
                    case TYPE_ATTR_INDIRECT:
                        if (is_black_attr(h5.token_start, h5.token_len) != AttributeType.TYPE_NONE) {
                            return true;
                        }
                        break;
                }
                attr = AttributeType.TYPE_NONE;
            } else if (h5.token_type == Html5Type.TAG_COMMENT) {
                if (h5.token_start.indexOf('`') != -1) {
                    return true;
                }
                
                if (h5.token_len > 3) {
                    char c0 = h5.token_start.charAt(0);
                    char c1 = h5.token_start.charAt(1);
                    char c2 = h5.token_start.charAt(2);
                    if (c0 == '[' &&
                        (c1 == 'i' || c1 == 'I') &&
                        (c2 == 'f' || c2 == 'F')) {
                        return true;
                    }
                    if ((c0 == 'x' || c0 == 'X') &&
                        (c1 == 'm' || c1 == 'M') &&
                        (c2 == 'l' || c2 == 'L')) {
                        return true;
                    }
                }
                
                if (h5.token_len > 5) {
                    if (cstrcasecmp_with_null("IMPORT", h5.token_start, 6) == 0) {
                        return true;
                    }
                    
                    if (cstrcasecmp_with_null("ENTITY", h5.token_start, 6) == 0) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    /**
     * Main XSS detection method that checks multiple parsing contexts.
     * <p>
     * This method tests the input in various HTML contexts (data state,
     * unquoted attributes, single-quoted, double-quoted, and back-quoted
     * attributes) to detect XSS attempts.
     * </p>
     * 
     * @param s the input string to analyze
     * @param len the length of the input
     * @return true if XSS is detected in any context, false otherwise
     */
    public static boolean libinjection_xss(String s, int len) {
        if (libinjection_is_xss(s, len, Html5Flags.DATA_STATE)) {
            return true;
        }
        if (libinjection_is_xss(s, len, Html5Flags.VALUE_NO_QUOTE)) {
            return true;
        }
        if (libinjection_is_xss(s, len, Html5Flags.VALUE_SINGLE_QUOTE)) {
            return true;
        }
        if (libinjection_is_xss(s, len, Html5Flags.VALUE_DOUBLE_QUOTE)) {
            return true;
        }
        if (libinjection_is_xss(s, len, Html5Flags.VALUE_BACK_QUOTE)) {
            return true;
        }
        
        return false;
    }
}