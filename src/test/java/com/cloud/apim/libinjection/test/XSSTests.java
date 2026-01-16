package com.cloud.apim.libinjection.test;

import com.cloud.apim.libinjection.impl.*;
import org.junit.Test;

import static org.junit.Assert.*;

public class XSSTests {

    @Test
    public void testIsXSS_scriptTag() {
        assertTrue(LibInjectionXSS.libinjection_xss("<script>alert(1);</script>", 26));
    }

    @Test
    public void testIsXSS_scriptTagWithPrefix1() {
        assertTrue(LibInjectionXSS.libinjection_xss("><script>alert(1);</script>", 27));
    }

    @Test
    public void testIsXSS_scriptTagWithPrefix2() {
        assertTrue(LibInjectionXSS.libinjection_xss("x ><script>alert(1);</script>", 29));
    }

    @Test
    public void testIsXSS_scriptTagWithPrefix3() {
        assertTrue(LibInjectionXSS.libinjection_xss("' ><script>alert(1);</script>", 29));
    }

    @Test
    public void testIsXSS_scriptTagWithPrefix4() {
        assertTrue(LibInjectionXSS.libinjection_xss("\"><script>alert(1);</script>", 28));
    }

    @Test
    public void testIsXSS_styleBreakout1() {
        assertTrue(LibInjectionXSS.libinjection_xss("red;</style><script>alert(1);</script>", 38));
    }

    @Test
    public void testIsXSS_styleBreakout2() {
        assertTrue(LibInjectionXSS.libinjection_xss("red;}</style><script>alert(1);</script>", 39));
    }

    @Test
    public void testIsXSS_styleBreakout3() {
        assertTrue(LibInjectionXSS.libinjection_xss("red;\"/><script>alert(1);</script>", 33));
    }

    @Test
    public void testIsXSS_styleBreakout4() {
        assertTrue(LibInjectionXSS.libinjection_xss("');}</style><script>alert(1);</script>", 38));
    }

    @Test
    public void testIsXSS_onerror1() {
        assertTrue(LibInjectionXSS.libinjection_xss("onerror=alert(1)>", 17));
    }

    @Test
    public void testIsXSS_onerror2() {
        assertTrue(LibInjectionXSS.libinjection_xss("x onerror=alert(1);>", 20));
    }

    @Test
    public void testIsXSS_onerror3() {
        assertTrue(LibInjectionXSS.libinjection_xss("x' onerror=alert(1);>", 21));
    }

    @Test
    public void testIsXSS_onerror4() {
        assertTrue(LibInjectionXSS.libinjection_xss("x\" onerror=alert(1);>", 21));
    }

    @Test
    public void testIsXSS_javascriptProtocol1() {
        assertTrue(LibInjectionXSS.libinjection_xss("<a href=\"javascript:alert(1)\">", 30));
    }

    @Test
    public void testIsXSS_javascriptProtocol2() {
        assertTrue(LibInjectionXSS.libinjection_xss("<a href='javascript:alert(1)'>", 30));
    }

    @Test
    public void testIsXSS_javascriptProtocol3() {
        assertTrue(LibInjectionXSS.libinjection_xss("<a href=javascript:alert(1)>", 28));
    }

    @Test
    public void testIsXSS_javascriptProtocol4() {
        assertTrue(LibInjectionXSS.libinjection_xss("<a href  =   javascript:alert(1); >", 35));
    }

    @Test
    public void testIsXSS_javascriptProtocol5() {
        assertTrue(LibInjectionXSS.libinjection_xss("<a href=\"  javascript:alert(1);\" >", 34));
    }

    @Test
    public void testIsXSS_javascriptProtocol6() {
        assertTrue(LibInjectionXSS.libinjection_xss("<a href=\"JAVASCRIPT:alert(1);\" >", 32));
    }

    @Test
    public void testIsXSS_animationHandler() {
        String input = "<style>@keyframes x{}</style><xss style=\"animation-name:x\" onanimationstart=\"alert(1)\"></xss>";
        assertTrue(LibInjectionXSS.libinjection_xss(input, input.length()));
    }

    @Test
    public void testIsXSS_noembed() {
        String input = "<noembed><img title=\"</noembed><img src onerror=alert(1)>\"></noembed>";
        assertTrue(LibInjectionXSS.libinjection_xss(input, input.length()));
    }

    @Test
    public void testIsXSS_polyglot() {
        String input = "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>";
        assertTrue(LibInjectionXSS.libinjection_xss(input, input.length()));
    }

    @Test
    public void testIsXSS_progressBarAnimated() {
        String input = "<xss class=progress-bar-animated onanimationstart=alert(1)>";
        assertTrue(LibInjectionXSS.libinjection_xss(input, input.length()));
    }

    @Test
    public void testIsXSS_popover() {
        String input = "<button popovertarget=x>Click me</button><xss ontoggle=alert(1) popover id=x>XSS</xss>";
        assertTrue(LibInjectionXSS.libinjection_xss(input, input.length()));
    }

    @Test
    public void testIsXSS_xmlNamespace() {
        String input = "<HTML xmlns:xss><?import namespace=\"xss\" implementation=\"%(htc)s\"><xss:xss>XSS</xss:xss></HTML>\"\"\",\"XML namespace.\"),(\"\"\"<XML ID=\"xss\"><I><B>&lt;IMG SRC=\"javas<!-- -->cript:javascript:alert(1)\"&gt;</B></I></XML><SPAN DATASRC=\"#xss\" DATAFLD=\"B\" DATAFORMATAS=\"HTML\"></SPAN>";
        assertTrue(LibInjectionXSS.libinjection_xss(input, input.length()));
    }

    // True negatives
    @Test
    public void testIsXSS_falsePositive1() {
        assertFalse(LibInjectionXSS.libinjection_xss("myvar=onfoobar==", 16));
    }

    @Test
    public void testIsXSS_falsePositive2() {
        // base64 encoded "thisisacookie", prefixed by "on"
        assertFalse(LibInjectionXSS.libinjection_xss("onY29va2llcw==", 14));
    }
    
    @Test
    public void testXSS_hrefAmpHash() {
        assertFalse(LibInjectionXSS.libinjection_xss("href=&#", 7));
    }

    @Test
    public void testXSS_hrefAmpHashX() {
        assertFalse(LibInjectionXSS.libinjection_xss("href=&#X", 8));
    }
}
