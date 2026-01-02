package com.cloud.apim.libinjection.impl;

import java.util.function.Function;

/**
 * HTML5 parser implementation for XSS detection.
 * <p>
 * This class implements an HTML5-compliant tokenizer that parses HTML content
 * and identifies potentially malicious patterns. It follows the HTML5 specification's
 * tokenization algorithm to accurately parse various HTML contexts including tags,
 * attributes, comments, and CDATA sections.
 * </p>
 * <p>
 * The parser uses a state machine approach where each state function processes
 * characters and transitions to the next appropriate state.
 * </p>
 */
public class LibInjectionHTML5 {
    
    private static final int CHAR_EOF = -1;
    private static final int CHAR_NULL = 0;
    private static final int CHAR_BANG = 33;
    private static final int CHAR_DOUBLE = 34;
    private static final int CHAR_PERCENT = 37;
    private static final int CHAR_SINGLE = 39;
    private static final int CHAR_DASH = 45;
    private static final int CHAR_SLASH = 47;
    private static final int CHAR_LT = 60;
    private static final int CHAR_EQUALS = 61;
    private static final int CHAR_GT = 62;
    private static final int CHAR_QUESTION = 63;
    private static final int CHAR_RIGHTB = 93;
    private static final int CHAR_TICK = 96;

    /**
     * Initializes the HTML5 parser state.
     * <p>
     * Sets up the initial state of the parser based on the provided flags,
     * which determine the parsing context (e.g., normal data, attribute value, etc.).
     * </p>
     * 
     * @param hs the HTML5 state object to initialize
     * @param s the input string to parse
     * @param len the length of the input string
     * @param flags the initial parsing context flags
     */
    public static void libinjection_h5_init(H5State hs, String s, int len, Html5Flags flags) {
        hs.s = s;
        hs.len = len;
        hs.pos = 0;
        hs.is_close = false;
        hs.token_start = null;
        hs.token_len = 0;
        hs.token_type = null;
        
        switch (flags) {
            case DATA_STATE:
                hs.state = LibInjectionHTML5::h5_state_data;
                break;
            case VALUE_NO_QUOTE:
                hs.state = LibInjectionHTML5::h5_state_before_attribute_name;
                break;
            case VALUE_SINGLE_QUOTE:
                hs.state = LibInjectionHTML5::h5_state_attribute_value_single_quote;
                break;
            case VALUE_DOUBLE_QUOTE:
                hs.state = LibInjectionHTML5::h5_state_attribute_value_double_quote;
                break;
            case VALUE_BACK_QUOTE:
                hs.state = LibInjectionHTML5::h5_state_attribute_value_back_quote;
                break;
        }
    }

    /**
     * Advances the parser to the next token.
     * <p>
     * Processes the input and extracts the next token according to the HTML5
     * tokenization rules. The token information is stored in the state object.
     * </p>
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was successfully extracted, 0 if end of input reached
     */
    public static int libinjection_h5_next(H5State hs) {
        return hs.state.apply(hs);
    }

    /**
     * Checks if a character is whitespace according to HTML5 specification.
     * 
     * @param ch the character to check
     * @return true if the character is whitespace, false otherwise
     */
    private static boolean h5_is_white(char ch) {
        return ch == ' ' || ch == '\t' || ch == '\n' || ch == 0x0B || ch == '\f' || ch == '\r';
    }

    /**
     * Skips whitespace characters in the input.
     * 
     * @param hs the HTML5 state object
     * @return the first non-whitespace character, or CHAR_EOF if end reached
     */
    private static int h5_skip_white(H5State hs) {
        char ch;
        while (hs.pos < hs.len) {
            ch = hs.s.charAt(hs.pos);
            switch (ch) {
                case 0x00:
                case 0x20:
                case 0x09:
                case 0x0A:
                case 0x0B:
                case 0x0C:
                case 0x0D:
                    hs.pos += 1;
                    break;
                default:
                    return ch;
            }
        }
        return CHAR_EOF;
    }

    /**
     * End-of-file state handler.
     * 
     * @param hs the HTML5 state object
     * @return 0 indicating no more tokens
     */
    private static int h5_state_eof(H5State hs) {
        return 0;
    }

    /**
     * Data state handler - processes plain text content.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_data(H5State hs) {
        int idx = hs.s.indexOf(CHAR_LT, hs.pos);
        if (idx == -1) {
            hs.token_start = hs.s.substring(hs.pos);
            hs.token_len = hs.len - hs.pos;
            hs.token_type = Html5Type.DATA_TEXT;
            hs.state = LibInjectionHTML5::h5_state_eof;
            if (hs.token_len == 0) {
                return 0;
            }
        } else {
            hs.token_start = hs.s.substring(hs.pos);
            hs.token_type = Html5Type.DATA_TEXT;
            hs.token_len = idx - hs.pos;
            hs.pos = idx + 1;
            hs.state = LibInjectionHTML5::h5_state_tag_open;
            if (hs.token_len == 0) {
                return h5_state_tag_open(hs);
            }
        }
        return 1;
    }

    /**
     * Tag open state handler - processes the character after '&lt;'.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_tag_open(H5State hs) {
        if (hs.pos >= hs.len) {
            return 0;
        }
        char ch = hs.s.charAt(hs.pos);
        if (ch == CHAR_BANG) {
            hs.pos += 1;
            return h5_state_markup_declaration_open(hs);
        } else if (ch == CHAR_SLASH) {
            hs.pos += 1;
            hs.is_close = true;
            return h5_state_end_tag_open(hs);
        } else if (ch == CHAR_QUESTION) {
            hs.pos += 1;
            return h5_state_bogus_comment(hs);
        } else if (ch == CHAR_PERCENT) {
            hs.pos += 1;
            return h5_state_bogus_comment2(hs);
        } else if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
            return h5_state_tag_name(hs);
        } else if (ch == CHAR_NULL) {
            return h5_state_tag_name(hs);
        } else {
            if (hs.pos == 0) {
                return h5_state_data(hs);
            }
            hs.token_start = hs.s.substring(hs.pos - 1, hs.pos);
            hs.token_len = 1;
            hs.token_type = Html5Type.DATA_TEXT;
            hs.state = LibInjectionHTML5::h5_state_data;
            return 1;
        }
    }

    /**
     * End tag open state handler - processes closing tags.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_end_tag_open(H5State hs) {
        if (hs.pos >= hs.len) {
            return 0;
        }
        char ch = hs.s.charAt(hs.pos);
        if (ch == CHAR_GT) {
            return h5_state_data(hs);
        } else if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
            return h5_state_tag_name(hs);
        }
        
        hs.is_close = false;
        return h5_state_bogus_comment(hs);
    }

    /**
     * Tag name close state handler - processes the closing '&gt;' of a tag.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_tag_name_close(H5State hs) {
        hs.is_close = false;
        hs.token_start = hs.s.substring(hs.pos, hs.pos + 1);
        hs.token_len = 1;
        hs.token_type = Html5Type.TAG_NAME_CLOSE;
        hs.pos += 1;
        if (hs.pos < hs.len) {
            hs.state = LibInjectionHTML5::h5_state_data;
        } else {
            hs.state = LibInjectionHTML5::h5_state_eof;
        }
        return 1;
    }

    /**
     * Tag name state handler - extracts tag names.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_tag_name(H5State hs) {
        char ch;
        int pos = hs.pos;
        while (pos < hs.len) {
            ch = hs.s.charAt(pos);
            if (ch == 0) {
                pos += 1;
            } else if (h5_is_white(ch)) {
                hs.token_start = hs.s.substring(hs.pos, pos);
                hs.token_len = pos - hs.pos;
                hs.token_type = Html5Type.TAG_NAME_OPEN;
                hs.pos = pos + 1;
                hs.state = LibInjectionHTML5::h5_state_before_attribute_name;
                return 1;
            } else if (ch == CHAR_SLASH) {
                hs.token_start = hs.s.substring(hs.pos, pos);
                hs.token_len = pos - hs.pos;
                hs.token_type = Html5Type.TAG_NAME_OPEN;
                hs.pos = pos + 1;
                hs.state = LibInjectionHTML5::h5_state_self_closing_start_tag;
                return 1;
            } else if (ch == CHAR_GT) {
                hs.token_start = hs.s.substring(hs.pos, pos);
                hs.token_len = pos - hs.pos;
                if (hs.is_close) {
                    hs.pos = pos + 1;
                    hs.is_close = false;
                    hs.token_type = Html5Type.TAG_CLOSE;
                    hs.state = LibInjectionHTML5::h5_state_data;
                } else {
                    hs.pos = pos;
                    hs.token_type = Html5Type.TAG_NAME_OPEN;
                    hs.state = LibInjectionHTML5::h5_state_tag_name_close;
                }
                return 1;
            } else {
                pos += 1;
            }
        }
        
        hs.token_start = hs.s.substring(hs.pos);
        hs.token_len = hs.len - hs.pos;
        hs.token_type = Html5Type.TAG_NAME_OPEN;
        hs.state = LibInjectionHTML5::h5_state_eof;
        return 1;
    }

    /**
     * Before attribute name state handler.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_before_attribute_name(H5State hs) {
        int ch = h5_skip_white(hs);
        switch (ch) {
            case CHAR_EOF:
                return 0;
            case CHAR_SLASH:
                hs.pos += 1;
                return h5_state_self_closing_start_tag(hs);
            case CHAR_GT:
                hs.state = LibInjectionHTML5::h5_state_data;
                hs.token_start = hs.s.substring(hs.pos, hs.pos + 1);
                hs.token_len = 1;
                hs.token_type = Html5Type.TAG_NAME_CLOSE;
                hs.pos += 1;
                return 1;
            default:
                return h5_state_attribute_name(hs);
        }
    }

    /**
     * Attribute name state handler - extracts attribute names.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_attribute_name(H5State hs) {
        char ch;
        int pos = hs.pos + 1;
        while (pos < hs.len) {
            ch = hs.s.charAt(pos);
            if (h5_is_white(ch)) {
                hs.token_start = hs.s.substring(hs.pos, pos);
                hs.token_len = pos - hs.pos;
                hs.token_type = Html5Type.ATTR_NAME;
                hs.state = LibInjectionHTML5::h5_state_after_attribute_name;
                hs.pos = pos + 1;
                return 1;
            } else if (ch == CHAR_SLASH) {
                hs.token_start = hs.s.substring(hs.pos, pos);
                hs.token_len = pos - hs.pos;
                hs.token_type = Html5Type.ATTR_NAME;
                hs.state = LibInjectionHTML5::h5_state_self_closing_start_tag;
                hs.pos = pos + 1;
                return 1;
            } else if (ch == CHAR_EQUALS) {
                hs.token_start = hs.s.substring(hs.pos, pos);
                hs.token_len = pos - hs.pos;
                hs.token_type = Html5Type.ATTR_NAME;
                hs.state = LibInjectionHTML5::h5_state_before_attribute_value;
                hs.pos = pos + 1;
                return 1;
            } else if (ch == CHAR_GT) {
                hs.token_start = hs.s.substring(hs.pos, pos);
                hs.token_len = pos - hs.pos;
                hs.token_type = Html5Type.ATTR_NAME;
                hs.state = LibInjectionHTML5::h5_state_tag_name_close;
                hs.pos = pos;
                return 1;
            } else {
                pos += 1;
            }
        }
        hs.token_start = hs.s.substring(hs.pos);
        hs.token_len = hs.len - hs.pos;
        hs.token_type = Html5Type.ATTR_NAME;
        hs.state = LibInjectionHTML5::h5_state_eof;
        hs.pos = hs.len;
        return 1;
    }

    /**
     * After attribute name state handler.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_after_attribute_name(H5State hs) {
        int c = h5_skip_white(hs);
        switch (c) {
            case CHAR_EOF:
                return 0;
            case CHAR_SLASH:
                hs.pos += 1;
                return h5_state_self_closing_start_tag(hs);
            case CHAR_EQUALS:
                hs.pos += 1;
                return h5_state_before_attribute_value(hs);
            case CHAR_GT:
                return h5_state_tag_name_close(hs);
            default:
                return h5_state_attribute_name(hs);
        }
    }

    /**
     * Before attribute value state handler.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_before_attribute_value(H5State hs) {
        int c = h5_skip_white(hs);
        
        if (c == CHAR_EOF) {
            hs.state = LibInjectionHTML5::h5_state_eof;
            return 0;
        }
        
        if (c == CHAR_DOUBLE) {
            return h5_state_attribute_value_double_quote(hs);
        } else if (c == CHAR_SINGLE) {
            return h5_state_attribute_value_single_quote(hs);
        } else if (c == CHAR_TICK) {
            return h5_state_attribute_value_back_quote(hs);
        } else {
            return h5_state_attribute_value_no_quote(hs);
        }
    }

    /**
     * Attribute value quote state handler - processes quoted attribute values.
     * 
     * @param hs the HTML5 state object
     * @param qchar the quote character (single, double, or back quote)
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_attribute_value_quote(H5State hs, char qchar) {
        if (hs.pos > 0) {
            hs.pos += 1;
        }
        
        int idx = hs.s.indexOf(qchar, hs.pos);
        if (idx == -1) {
            hs.token_start = hs.s.substring(hs.pos);
            hs.token_len = hs.len - hs.pos;
            hs.token_type = Html5Type.ATTR_VALUE;
            hs.state = LibInjectionHTML5::h5_state_eof;
        } else {
            hs.token_start = hs.s.substring(hs.pos, idx);
            hs.token_len = idx - hs.pos;
            hs.token_type = Html5Type.ATTR_VALUE;
            hs.state = LibInjectionHTML5::h5_state_after_attribute_value_quoted_state;
            hs.pos = idx + 1;
        }
        return 1;
    }

    /**
     * Attribute value double quote state handler.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_attribute_value_double_quote(H5State hs) {
        return h5_state_attribute_value_quote(hs, (char) CHAR_DOUBLE);
    }

    /**
     * Attribute value single quote state handler.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_attribute_value_single_quote(H5State hs) {
        return h5_state_attribute_value_quote(hs, (char) CHAR_SINGLE);
    }

    /**
     * Attribute value back quote state handler.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_attribute_value_back_quote(H5State hs) {
        return h5_state_attribute_value_quote(hs, (char) CHAR_TICK);
    }

    /**
     * Attribute value no quote state handler - processes unquoted attribute values.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_attribute_value_no_quote(H5State hs) {
        char ch;
        int pos = hs.pos;
        while (pos < hs.len) {
            ch = hs.s.charAt(pos);
            if (h5_is_white(ch)) {
                hs.token_type = Html5Type.ATTR_VALUE;
                hs.token_start = hs.s.substring(hs.pos, pos);
                hs.token_len = pos - hs.pos;
                hs.pos = pos + 1;
                hs.state = LibInjectionHTML5::h5_state_before_attribute_name;
                return 1;
            } else if (ch == CHAR_GT) {
                hs.token_type = Html5Type.ATTR_VALUE;
                hs.token_start = hs.s.substring(hs.pos, pos);
                hs.token_len = pos - hs.pos;
                hs.pos = pos;
                hs.state = LibInjectionHTML5::h5_state_tag_name_close;
                return 1;
            }
            pos += 1;
        }
        hs.state = LibInjectionHTML5::h5_state_eof;
        hs.token_start = hs.s.substring(hs.pos);
        hs.token_len = hs.len - hs.pos;
        hs.token_type = Html5Type.ATTR_VALUE;
        return 1;
    }

    /**
     * After attribute value quoted state handler.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_after_attribute_value_quoted_state(H5State hs) {
        if (hs.pos >= hs.len) {
            return 0;
        }
        char ch = hs.s.charAt(hs.pos);
        if (h5_is_white(ch)) {
            hs.pos += 1;
            return h5_state_before_attribute_name(hs);
        } else if (ch == CHAR_SLASH) {
            hs.pos += 1;
            return h5_state_self_closing_start_tag(hs);
        } else if (ch == CHAR_GT) {
            hs.token_start = hs.s.substring(hs.pos, hs.pos + 1);
            hs.token_len = 1;
            hs.token_type = Html5Type.TAG_NAME_CLOSE;
            hs.pos += 1;
            hs.state = LibInjectionHTML5::h5_state_data;
            return 1;
        } else {
            return h5_state_before_attribute_name(hs);
        }
    }

    /**
     * Self-closing start tag state handler - processes self-closing tags like &lt;br/&gt;.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_self_closing_start_tag(H5State hs) {
        if (hs.pos >= hs.len) {
            return 0;
        }
        char ch = hs.s.charAt(hs.pos);
        if (ch == CHAR_GT) {
            hs.token_start = hs.s.substring(hs.pos - 1, hs.pos + 1);
            hs.token_len = 2;
            hs.token_type = Html5Type.TAG_NAME_SELFCLOSE;
            hs.state = LibInjectionHTML5::h5_state_data;
            hs.pos += 1;
            return 1;
        } else {
            return h5_state_before_attribute_name(hs);
        }
    }

    /**
     * Bogus comment state handler - handles malformed comments.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_bogus_comment(H5State hs) {
        int idx = hs.s.indexOf(CHAR_GT, hs.pos);
        if (idx == -1) {
            hs.token_start = hs.s.substring(hs.pos);
            hs.token_len = hs.len - hs.pos;
            hs.pos = hs.len;
            hs.state = LibInjectionHTML5::h5_state_eof;
        } else {
            hs.token_start = hs.s.substring(hs.pos, idx);
            hs.token_len = idx - hs.pos;
            hs.pos = idx + 1;
            hs.state = LibInjectionHTML5::h5_state_data;
        }
        
        hs.token_type = Html5Type.TAG_COMMENT;
        return 1;
    }

    /**
     * Bogus comment state handler for percent-delimited comments.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_bogus_comment2(H5State hs) {
        int pos = hs.pos;
        while (true) {
            int idx = hs.s.indexOf(CHAR_PERCENT, pos);
            if (idx == -1 || idx + 1 >= hs.len) {
                hs.token_start = hs.s.substring(hs.pos);
                hs.token_len = hs.len - hs.pos;
                hs.pos = hs.len;
                hs.token_type = Html5Type.TAG_COMMENT;
                hs.state = LibInjectionHTML5::h5_state_eof;
                return 1;
            }
            
            if (hs.s.charAt(idx + 1) != CHAR_GT) {
                pos = idx + 1;
                continue;
            }
            
            hs.token_start = hs.s.substring(hs.pos, idx);
            hs.token_len = idx - hs.pos;
            hs.pos = idx + 2;
            hs.state = LibInjectionHTML5::h5_state_data;
            hs.token_type = Html5Type.TAG_COMMENT;
            return 1;
        }
    }

    /**
     * Markup declaration open state handler - processes DOCTYPE, CDATA, and comments.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_markup_declaration_open(H5State hs) {
        int remaining = hs.len - hs.pos;
        if (remaining >= 7 &&
            (hs.s.charAt(hs.pos + 0) == 'D' || hs.s.charAt(hs.pos + 0) == 'd') &&
            (hs.s.charAt(hs.pos + 1) == 'O' || hs.s.charAt(hs.pos + 1) == 'o') &&
            (hs.s.charAt(hs.pos + 2) == 'C' || hs.s.charAt(hs.pos + 2) == 'c') &&
            (hs.s.charAt(hs.pos + 3) == 'T' || hs.s.charAt(hs.pos + 3) == 't') &&
            (hs.s.charAt(hs.pos + 4) == 'Y' || hs.s.charAt(hs.pos + 4) == 'y') &&
            (hs.s.charAt(hs.pos + 5) == 'P' || hs.s.charAt(hs.pos + 5) == 'p') &&
            (hs.s.charAt(hs.pos + 6) == 'E' || hs.s.charAt(hs.pos + 6) == 'e')) {
            return h5_state_doctype(hs);
        } else if (remaining >= 7 &&
                   hs.s.charAt(hs.pos + 0) == '[' &&
                   hs.s.charAt(hs.pos + 1) == 'C' &&
                   hs.s.charAt(hs.pos + 2) == 'D' &&
                   hs.s.charAt(hs.pos + 3) == 'A' &&
                   hs.s.charAt(hs.pos + 4) == 'T' &&
                   hs.s.charAt(hs.pos + 5) == 'A' &&
                   hs.s.charAt(hs.pos + 6) == '[') {
            hs.pos += 7;
            return h5_state_cdata(hs);
        } else if (remaining >= 2 &&
                   hs.s.charAt(hs.pos + 0) == '-' &&
                   hs.s.charAt(hs.pos + 1) == '-') {
            hs.pos += 2;
            return h5_state_comment(hs);
        }
        
        return h5_state_bogus_comment(hs);
    }

    /**
     * Comment state handler - processes HTML comments.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_comment(H5State hs) {
        char ch;
        int pos = hs.pos;
        while (true) {
            int idx = hs.s.indexOf(CHAR_DASH, pos);
            
            if (idx == -1 || idx > hs.len - 3) {
                hs.state = LibInjectionHTML5::h5_state_eof;
                hs.token_start = hs.s.substring(hs.pos);
                hs.token_len = hs.len - hs.pos;
                hs.token_type = Html5Type.TAG_COMMENT;
                return 1;
            }
            int offset = 1;
            
            while (idx + offset < hs.len && hs.s.charAt(idx + offset) == 0) {
                offset += 1;
            }
            if (idx + offset == hs.len) {
                hs.state = LibInjectionHTML5::h5_state_eof;
                hs.token_start = hs.s.substring(hs.pos);
                hs.token_len = hs.len - hs.pos;
                hs.token_type = Html5Type.TAG_COMMENT;
                return 1;
            }
            
            ch = hs.s.charAt(idx + offset);
            if (ch != CHAR_DASH && ch != CHAR_BANG) {
                pos = idx + 1;
                continue;
            }
            
            offset += 1;
            if (idx + offset == hs.len) {
                hs.state = LibInjectionHTML5::h5_state_eof;
                hs.token_start = hs.s.substring(hs.pos);
                hs.token_len = hs.len - hs.pos;
                hs.token_type = Html5Type.TAG_COMMENT;
                return 1;
            }
            
            ch = hs.s.charAt(idx + offset);
            if (ch != CHAR_GT) {
                pos = idx + 1;
                continue;
            }
            offset += 1;
            
            hs.token_start = hs.s.substring(hs.pos, idx);
            hs.token_len = idx - hs.pos;
            hs.pos = idx + offset;
            hs.state = LibInjectionHTML5::h5_state_data;
            hs.token_type = Html5Type.TAG_COMMENT;
            return 1;
        }
    }

    /**
     * CDATA section state handler - processes CDATA sections.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_cdata(H5State hs) {
        int pos = hs.pos;
        while (true) {
            int idx = hs.s.indexOf(CHAR_RIGHTB, pos);
            
            if (idx == -1 || idx > hs.len - 3) {
                hs.state = LibInjectionHTML5::h5_state_eof;
                hs.token_start = hs.s.substring(hs.pos);
                hs.token_len = hs.len - hs.pos;
                hs.token_type = Html5Type.DATA_TEXT;
                return 1;
            } else if (hs.s.charAt(idx + 1) == CHAR_RIGHTB && hs.s.charAt(idx + 2) == CHAR_GT) {
                hs.state = LibInjectionHTML5::h5_state_data;
                hs.token_start = hs.s.substring(hs.pos, idx);
                hs.token_len = idx - hs.pos;
                hs.pos = idx + 3;
                hs.token_type = Html5Type.DATA_TEXT;
                return 1;
            } else {
                pos = idx + 1;
            }
        }
    }

    /**
     * DOCTYPE state handler - processes DOCTYPE declarations.
     * 
     * @param hs the HTML5 state object
     * @return 1 if a token was extracted, 0 otherwise
     */
    private static int h5_state_doctype(H5State hs) {
        hs.token_start = hs.s.substring(hs.pos);
        hs.token_type = Html5Type.DOCTYPE;
        
        int idx = hs.s.indexOf(CHAR_GT, hs.pos);
        if (idx == -1) {
            hs.state = LibInjectionHTML5::h5_state_eof;
            hs.token_len = hs.len - hs.pos;
        } else {
            hs.state = LibInjectionHTML5::h5_state_data;
            hs.token_len = idx - hs.pos;
            hs.pos = idx + 1;
        }
        return 1;
    }
}
