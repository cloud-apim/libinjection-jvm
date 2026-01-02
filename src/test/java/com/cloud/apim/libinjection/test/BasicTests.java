package com.cloud.apim.libinjection.test;

import com.cloud.apim.libinjection.impl.LibInjectionSQLi;
import com.cloud.apim.libinjection.impl.LibInjectionXSS;
import org.junit.Test;
import static org.junit.Assert.*;

public class BasicTests {
    
    @Test
    public void testSQLiDetectionWithBasicInjection() {
        String maliciousInput = "1' OR '1'='1";
        assertTrue("Should detect basic SQL injection", LibInjectionSQLi.libinjection_is_sqli(maliciousInput));
    }
    
    @Test
    public void testSQLiDetectionWithUnionAttack() {
        String maliciousInput = "1 UNION SELECT * FROM users";
        assertTrue("Should detect UNION-based SQL injection", LibInjectionSQLi.libinjection_is_sqli(maliciousInput));
    }
    
    @Test
    public void testSQLiDetectionWithCleanInput() {
        String cleanInput = "john.doe@example.com";
        assertFalse("Should not detect SQL injection in clean input", LibInjectionSQLi.libinjection_is_sqli(cleanInput));
    }
    
    @Test
    public void testSQLiDetectionWithNullInput() {
        assertFalse("Should return false for null input", LibInjectionSQLi.libinjection_is_sqli(null));
    }
    
    @Test
    public void testSQLiDetectionWithEmptyString() {
        assertFalse("Should return false for empty string", LibInjectionSQLi.libinjection_is_sqli(""));
    }
    
    @Test
    public void testSQLiDetectionWithNumericInput() {
        String numericInput = "12345";
        assertFalse("Should not detect SQL injection in numeric input", LibInjectionSQLi.libinjection_is_sqli(numericInput));
    }
    
    @Test
    public void testXSSDetectionWithScriptTag() {
        String maliciousInput = "<script>alert('XSS')</script>";
        assertTrue("Should detect XSS with script tag", LibInjectionXSS.libinjection_xss(maliciousInput, maliciousInput.length()));
    }
    
    @Test
    public void testXSSDetectionWithImgOnError() {
        String maliciousInput = "<img src=x onerror=alert('XSS')>";
        assertTrue("Should detect XSS with img onerror", LibInjectionXSS.libinjection_xss(maliciousInput, maliciousInput.length()));
    }
    
    @Test
    public void testXSSDetectionWithJavascriptProtocol() {
        String maliciousInput = "<a href='javascript:alert(1)'>click</a>";
        assertTrue("Should detect XSS with javascript: protocol", LibInjectionXSS.libinjection_xss(maliciousInput, maliciousInput.length()));
    }
    
    @Test
    public void testXSSDetectionWithIframe() {
        String maliciousInput = "<iframe src='http://evil.com'></iframe>";
        assertTrue("Should detect XSS with iframe tag", LibInjectionXSS.libinjection_xss(maliciousInput, maliciousInput.length()));
    }
    
    @Test
    public void testXSSDetectionWithCleanHTML() {
        String cleanInput = "<p>Hello World</p>";
        assertFalse("Should not detect XSS in clean HTML", LibInjectionXSS.libinjection_xss(cleanInput, cleanInput.length()));
    }
    
    @Test
    public void testXSSDetectionWithPlainText() {
        String plainText = "This is just plain text";
        assertFalse("Should not detect XSS in plain text", LibInjectionXSS.libinjection_xss(plainText, plainText.length()));
    }
    
    @Test
    public void testXSSDetectionWithEmptyString() {
        String emptyString = "";
        assertFalse("Should not detect XSS in empty string", LibInjectionXSS.libinjection_xss(emptyString, emptyString.length()));
    }
}
