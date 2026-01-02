package com.cloud.apim.libinjection.impl;

/**
 * Enumeration of HTML5 token types.
 * <p>
 * These types represent the different kinds of tokens that can be identified
 * during HTML5 parsing for XSS detection.
 * </p>
 */
public enum Html5Type {
    
    /**
     * Plain text data between tags.
     */
    DATA_TEXT,
    
    /**
     * Opening tag name (e.g., "div" in &lt;div&gt;).
     */
    TAG_NAME_OPEN,
    
    /**
     * Closing tag name (e.g., "div" in &lt;/div&gt;).
     */
    TAG_NAME_CLOSE,
    
    /**
     * Self-closing tag (e.g., &lt;br/&gt;).
     */
    TAG_NAME_SELFCLOSE,
    
    /**
     * Data within a tag.
     */
    TAG_DATA,
    
    /**
     * Tag closing delimiter (&gt;).
     */
    TAG_CLOSE,
    
    /**
     * Attribute name within a tag.
     */
    ATTR_NAME,
    
    /**
     * Attribute value within a tag.
     */
    ATTR_VALUE,
    
    /**
     * HTML comment (&lt;!-- ... --&gt;).
     */
    TAG_COMMENT,
    
    /**
     * DOCTYPE declaration.
     */
    DOCTYPE
}
