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

    /**
     * JavaScript event handler names (without "on" prefix) that are blacklisted.
     * Extracted from WebKit, Chromium/Blink, Firefox/Gecko and W3C/WHATWG specs.
     */
    private static final StringType[] BLACKATTREVENT = new StringType[] {
        new StringType("ABORT", AttributeType.TYPE_BLACK),
        new StringType("ACCESSKEYNOTFOUND", AttributeType.TYPE_BLACK),
        new StringType("ACTIVATE", AttributeType.TYPE_BLACK),
        new StringType("ACTIVE", AttributeType.TYPE_BLACK),
        new StringType("ADDSOURCEBUFFER", AttributeType.TYPE_BLACK),
        new StringType("ADDSTREAM", AttributeType.TYPE_BLACK),
        new StringType("ADDTRACK", AttributeType.TYPE_BLACK),
        new StringType("AFTERPAINT", AttributeType.TYPE_BLACK),
        new StringType("AFTERPRINT", AttributeType.TYPE_BLACK),
        new StringType("AFTERSCRIPTEXECUTE", AttributeType.TYPE_BLACK),
        new StringType("ANIMATIONCANCEL", AttributeType.TYPE_BLACK),
        new StringType("ANIMATIONEND", AttributeType.TYPE_BLACK),
        new StringType("ANIMATIONITERATION", AttributeType.TYPE_BLACK),
        new StringType("ANIMATIONSTART", AttributeType.TYPE_BLACK),
        new StringType("AUDIOEND", AttributeType.TYPE_BLACK),
        new StringType("AUDIOCOMPLETE", AttributeType.TYPE_BLACK),
        new StringType("AUDIOPROCESS", AttributeType.TYPE_BLACK),
        new StringType("AUDIOSTART", AttributeType.TYPE_BLACK),
        new StringType("AUTOCOMPLETE", AttributeType.TYPE_BLACK),
        new StringType("AUTOCOMPLETEERROR", AttributeType.TYPE_BLACK),
        new StringType("AUXCLICK", AttributeType.TYPE_BLACK),
        new StringType("BACKGROUNDFETCHABORT", AttributeType.TYPE_BLACK),
        new StringType("BACKGROUNDFETCHCLICK", AttributeType.TYPE_BLACK),
        new StringType("BACKGROUNDFETCHFAIL", AttributeType.TYPE_BLACK),
        new StringType("BACKGROUNDFETCHSUCCESS", AttributeType.TYPE_BLACK),
        new StringType("BEFOREACTIVATE", AttributeType.TYPE_BLACK),
        new StringType("BEFORECOPY", AttributeType.TYPE_BLACK),
        new StringType("BEFORECUT", AttributeType.TYPE_BLACK),
        new StringType("BEFOREINPUT", AttributeType.TYPE_BLACK),
        new StringType("BEFORELOAD", AttributeType.TYPE_BLACK),
        new StringType("BEFOREMATCH", AttributeType.TYPE_BLACK),
        new StringType("BEFOREPASTE", AttributeType.TYPE_BLACK),
        new StringType("BEFOREPRINT", AttributeType.TYPE_BLACK),
        new StringType("BEFORESCRIPTEXECUTE", AttributeType.TYPE_BLACK),
        new StringType("BEFORETOGGLE", AttributeType.TYPE_BLACK),
        new StringType("BEFOREUNLOAD", AttributeType.TYPE_BLACK),
        new StringType("BEGINEVENT", AttributeType.TYPE_BLACK),
        new StringType("BLOCKED", AttributeType.TYPE_BLACK),
        new StringType("BLUR", AttributeType.TYPE_BLACK),
        new StringType("BOUNDARY", AttributeType.TYPE_BLACK),
        new StringType("BUFFEREDAMOUNTLOW", AttributeType.TYPE_BLACK),
        new StringType("BUFFEREDCHANGE", AttributeType.TYPE_BLACK),
        new StringType("CACHED", AttributeType.TYPE_BLACK),
        new StringType("CANCEL", AttributeType.TYPE_BLACK),
        new StringType("CANPLAY", AttributeType.TYPE_BLACK),
        new StringType("CANPLAYTHROUGH", AttributeType.TYPE_BLACK),
        new StringType("CHANGE", AttributeType.TYPE_BLACK),
        new StringType("CHARGINGCHANGE", AttributeType.TYPE_BLACK),
        new StringType("CHARGINGTIMECHANGE", AttributeType.TYPE_BLACK),
        new StringType("CHECKING", AttributeType.TYPE_BLACK),
        new StringType("CLICK", AttributeType.TYPE_BLACK),
        new StringType("CLOSE", AttributeType.TYPE_BLACK),
        new StringType("CLOSING", AttributeType.TYPE_BLACK),
        new StringType("COMPLETE", AttributeType.TYPE_BLACK),
        new StringType("COMPOSITIONEND", AttributeType.TYPE_BLACK),
        new StringType("COMPOSITIONSTART", AttributeType.TYPE_BLACK),
        new StringType("COMPOSITIONCHANGE", AttributeType.TYPE_BLACK),
        new StringType("COMPOSITIONUPDATE", AttributeType.TYPE_BLACK),
        new StringType("COMMAND", AttributeType.TYPE_BLACK),
        new StringType("CONFIGURATIONCHANGE", AttributeType.TYPE_BLACK),
        new StringType("CONNECT", AttributeType.TYPE_BLACK),
        new StringType("CONNECTING", AttributeType.TYPE_BLACK),
        new StringType("CONNECTIONSTATECHANGE", AttributeType.TYPE_BLACK),
        new StringType("CONTENTVISIBILITYAUTOSTATECHANGE", AttributeType.TYPE_BLACK),
        new StringType("CONTEXTLOST", AttributeType.TYPE_BLACK),
        new StringType("CONTEXTMENU", AttributeType.TYPE_BLACK),
        new StringType("CONTEXTRESTORED", AttributeType.TYPE_BLACK),
        new StringType("CONTROLLERCHANGE", AttributeType.TYPE_BLACK),
        new StringType("COOKIECHANGE", AttributeType.TYPE_BLACK),
        new StringType("COORDINATORSTATECHANGE", AttributeType.TYPE_BLACK),
        new StringType("COPY", AttributeType.TYPE_BLACK),
        new StringType("COUPONCODECHANGED", AttributeType.TYPE_BLACK),
        new StringType("CUECHANGE", AttributeType.TYPE_BLACK),
        new StringType("CURRENTENTRYCHANGE", AttributeType.TYPE_BLACK),
        new StringType("CUT", AttributeType.TYPE_BLACK),
        new StringType("DATAAVAILABLE", AttributeType.TYPE_BLACK),
        new StringType("DATACHANNEL", AttributeType.TYPE_BLACK),
        new StringType("DBLCLICK", AttributeType.TYPE_BLACK),
        new StringType("DEQUEUE", AttributeType.TYPE_BLACK),
        new StringType("DEVICECHANGE", AttributeType.TYPE_BLACK),
        new StringType("DEVICELIGHT", AttributeType.TYPE_BLACK),
        new StringType("DEVICEMOTION", AttributeType.TYPE_BLACK),
        new StringType("DEVICEORIENTATION", AttributeType.TYPE_BLACK),
        new StringType("DEVICEORIENTATIONABSOLUTE", AttributeType.TYPE_BLACK),
        new StringType("DISCHARGINGTIMECHANGE", AttributeType.TYPE_BLACK),
        new StringType("DISCONNECT", AttributeType.TYPE_BLACK),
        new StringType("DISPOSE", AttributeType.TYPE_BLACK),
        new StringType("DOMACTIVATE", AttributeType.TYPE_BLACK),
        new StringType("DOMCHARACTERDATAMODIFIED", AttributeType.TYPE_BLACK),
        new StringType("DOMCONTENTLOADED", AttributeType.TYPE_BLACK),
        new StringType("DOMNODEINSERTED", AttributeType.TYPE_BLACK),
        new StringType("DOMNODEINSERTEDINTODOCUMENT", AttributeType.TYPE_BLACK),
        new StringType("DOMNODEREMOVED", AttributeType.TYPE_BLACK),
        new StringType("DOMNODEREMOVEDFROMDOCUMENT", AttributeType.TYPE_BLACK),
        new StringType("DOMSUBTREEMODIFIED", AttributeType.TYPE_BLACK),
        new StringType("DOWNLOADING", AttributeType.TYPE_BLACK),
        new StringType("DRAG", AttributeType.TYPE_BLACK),
        new StringType("DRAGEND", AttributeType.TYPE_BLACK),
        new StringType("DRAGENTER", AttributeType.TYPE_BLACK),
        new StringType("DRAGLEAVE", AttributeType.TYPE_BLACK),
        new StringType("DRAGEXIT", AttributeType.TYPE_BLACK),
        new StringType("DRAGOVER", AttributeType.TYPE_BLACK),
        new StringType("DRAGSTART", AttributeType.TYPE_BLACK),
        new StringType("DROP", AttributeType.TYPE_BLACK),
        new StringType("DURATIONCHANGE", AttributeType.TYPE_BLACK),
        new StringType("EMPTIED", AttributeType.TYPE_BLACK),
        new StringType("ENCRYPTED", AttributeType.TYPE_BLACK),
        new StringType("EDGEUICANCELED", AttributeType.TYPE_BLACK),
        new StringType("EDGEUICOMPLETED", AttributeType.TYPE_BLACK),
        new StringType("EDGEUISTARTED", AttributeType.TYPE_BLACK),
        new StringType("EDITORBEFOREINPUT", AttributeType.TYPE_BLACK),
        new StringType("EDITORINPUT", AttributeType.TYPE_BLACK),
        new StringType("END", AttributeType.TYPE_BLACK),
        new StringType("ENDED", AttributeType.TYPE_BLACK),
        new StringType("ENDEVENT", AttributeType.TYPE_BLACK),
        new StringType("ENDSTREAMING", AttributeType.TYPE_BLACK),
        new StringType("ENTER", AttributeType.TYPE_BLACK),
        new StringType("ENTERPICTUREINPICTURE", AttributeType.TYPE_BLACK),
        new StringType("ERROR", AttributeType.TYPE_BLACK),
        new StringType("EXIT", AttributeType.TYPE_BLACK),
        new StringType("FENCEDTREECLICK", AttributeType.TYPE_BLACK),
        new StringType("FETCH", AttributeType.TYPE_BLACK),
        new StringType("FINISH", AttributeType.TYPE_BLACK),
        new StringType("FOCUS", AttributeType.TYPE_BLACK),
        new StringType("FOCUSIN", AttributeType.TYPE_BLACK),
        new StringType("FOCUSOUT", AttributeType.TYPE_BLACK),
        new StringType("FORMCHANGE", AttributeType.TYPE_BLACK),
        new StringType("FORMCHECKBOXSTATECHANGE", AttributeType.TYPE_BLACK),
        new StringType("FORMDATA", AttributeType.TYPE_BLACK),
        new StringType("FORMINVALID", AttributeType.TYPE_BLACK),
        new StringType("FORMRADIOSTATECHANGE", AttributeType.TYPE_BLACK),
        new StringType("FORMRESET", AttributeType.TYPE_BLACK),
        new StringType("FORMSELECT", AttributeType.TYPE_BLACK),
        new StringType("FORMSUBMIT", AttributeType.TYPE_BLACK),
        new StringType("FULLSCREENCHANGE", AttributeType.TYPE_BLACK),
        new StringType("FULLSCREENERROR", AttributeType.TYPE_BLACK),
        new StringType("GAMEPADAXISMOVE", AttributeType.TYPE_BLACK),
        new StringType("GAMEPADBUTTONDOWN", AttributeType.TYPE_BLACK),
        new StringType("GAMEPADBUTTONUP", AttributeType.TYPE_BLACK),
        new StringType("GAMEPADCONNECTED", AttributeType.TYPE_BLACK),
        new StringType("GAMEPADDISCONNECTED", AttributeType.TYPE_BLACK),
        new StringType("GATHERINGSTATECHANGE", AttributeType.TYPE_BLACK),
        new StringType("GESTURECHANGE", AttributeType.TYPE_BLACK),
        new StringType("GESTUREEND", AttributeType.TYPE_BLACK),
        new StringType("GESTURESCROLLEND", AttributeType.TYPE_BLACK),
        new StringType("GESTURESCROLLSTART", AttributeType.TYPE_BLACK),
        new StringType("GESTURESCROLLUPDATE", AttributeType.TYPE_BLACK),
        new StringType("GESTURESTART", AttributeType.TYPE_BLACK),
        new StringType("GESTURETAP", AttributeType.TYPE_BLACK),
        new StringType("GESTURETAPDOWN", AttributeType.TYPE_BLACK),
        new StringType("GOTPOINTERCAPTURE", AttributeType.TYPE_BLACK),
        new StringType("HASHCHANGE", AttributeType.TYPE_BLACK),
        new StringType("ICECANDIDATE", AttributeType.TYPE_BLACK),
        new StringType("ICECANDIDATEERROR", AttributeType.TYPE_BLACK),
        new StringType("ICECONNECTIONSTATECHANGE", AttributeType.TYPE_BLACK),
        new StringType("ICEGATHERINGSTATECHANGE", AttributeType.TYPE_BLACK),
        new StringType("IMAGEABORT", AttributeType.TYPE_BLACK),
        new StringType("INACTIVE", AttributeType.TYPE_BLACK),
        new StringType("INPUT", AttributeType.TYPE_BLACK),
        new StringType("INPUTSOURCESCHANGE", AttributeType.TYPE_BLACK),
        new StringType("INSTALL", AttributeType.TYPE_BLACK),
        new StringType("INVALID", AttributeType.TYPE_BLACK),
        new StringType("INVOKE", AttributeType.TYPE_BLACK),
        new StringType("KEYDOWN", AttributeType.TYPE_BLACK),
        new StringType("KEYPRESS", AttributeType.TYPE_BLACK),
        new StringType("KEYSTATUSESCHANGE", AttributeType.TYPE_BLACK),
        new StringType("KEYUP", AttributeType.TYPE_BLACK),
        new StringType("LANGUAGECHANGE", AttributeType.TYPE_BLACK),
        new StringType("LEAVEPICTUREINPICTURE", AttributeType.TYPE_BLACK),
        new StringType("LEGACYATTRMODIFIED", AttributeType.TYPE_BLACK),
        new StringType("LEGACYCHARACTERDATAMODIFIED", AttributeType.TYPE_BLACK),
        new StringType("LEGACYDOMACTIVATE", AttributeType.TYPE_BLACK),
        new StringType("LEGACYDOMFOCUSIN", AttributeType.TYPE_BLACK),
        new StringType("LEGACYDOMFOCUSOUT", AttributeType.TYPE_BLACK),
        new StringType("LEGACYMOUSELINEORPAGESCROLL", AttributeType.TYPE_BLACK),
        new StringType("LEGACYMOUSEPIXELSCROLL", AttributeType.TYPE_BLACK),
        new StringType("LEGACYNODEINSERTED", AttributeType.TYPE_BLACK),
        new StringType("LEGACYNODEINSERTEDINTODOCUMENT", AttributeType.TYPE_BLACK),
        new StringType("LEGACYNODEREMOVED", AttributeType.TYPE_BLACK),
        new StringType("LEGACYNODEREMOVEDFROMDOCUMENT", AttributeType.TYPE_BLACK),
        new StringType("LEGACYSUBTREEMODIFIED", AttributeType.TYPE_BLACK),
        new StringType("LEGACYTEXTINPUT", AttributeType.TYPE_BLACK),
        new StringType("LEVELCHANGE", AttributeType.TYPE_BLACK),
        new StringType("LOAD", AttributeType.TYPE_BLACK),
        new StringType("LOADEDDATA", AttributeType.TYPE_BLACK),
        new StringType("LOADEDMETADATA", AttributeType.TYPE_BLACK),
        new StringType("LOADEND", AttributeType.TYPE_BLACK),
        new StringType("LOADING", AttributeType.TYPE_BLACK),
        new StringType("LOADINGDONE", AttributeType.TYPE_BLACK),
        new StringType("LOADINGERROR", AttributeType.TYPE_BLACK),
        new StringType("LOADSTART", AttributeType.TYPE_BLACK),
        new StringType("LOSTPOINTERCAPTURE", AttributeType.TYPE_BLACK),
        new StringType("MAGNIFYGESTURE", AttributeType.TYPE_BLACK),
        new StringType("MAGNIFYGESTURESTART", AttributeType.TYPE_BLACK),
        new StringType("MAGNIFYGESTUREUPDATE", AttributeType.TYPE_BLACK),
        new StringType("MARK", AttributeType.TYPE_BLACK),
        new StringType("MEDIARECORDERDATAAVAILABLE", AttributeType.TYPE_BLACK),
        new StringType("MEDIARECORDERSTOP", AttributeType.TYPE_BLACK),
        new StringType("MEDIARECORDERWARNING", AttributeType.TYPE_BLACK),
        new StringType("MERCHANTVALIDATION", AttributeType.TYPE_BLACK),
        new StringType("MESSAGE", AttributeType.TYPE_BLACK),
        new StringType("MESSAGEERROR", AttributeType.TYPE_BLACK),
        new StringType("MOUSEDOUBLECLICK", AttributeType.TYPE_BLACK),
        new StringType("MOUSEDOWN", AttributeType.TYPE_BLACK),
        new StringType("MOUSEENTER", AttributeType.TYPE_BLACK),
        new StringType("MOUSEEXPLOREBYTOUCH", AttributeType.TYPE_BLACK),
        new StringType("MOUSEHITTEST", AttributeType.TYPE_BLACK),
        new StringType("MOUSELEAVE", AttributeType.TYPE_BLACK),
        new StringType("MOUSELONGTAP", AttributeType.TYPE_BLACK),
        new StringType("MOUSEMOVE", AttributeType.TYPE_BLACK),
        new StringType("MOUSEOUT", AttributeType.TYPE_BLACK),
        new StringType("MOUSEOVER", AttributeType.TYPE_BLACK),
        new StringType("MOUSEUP", AttributeType.TYPE_BLACK),
        new StringType("MOUSEWHEEL", AttributeType.TYPE_BLACK),
        new StringType("MOZFULLSCREENCHANGE", AttributeType.TYPE_BLACK),
        new StringType("MOZFULLSCREENERROR", AttributeType.TYPE_BLACK),
        new StringType("MOZPOINTERLOCKCHANGE", AttributeType.TYPE_BLACK),
        new StringType("MOZPOINTERLOCKERROR", AttributeType.TYPE_BLACK),
        new StringType("MOZVISUALRESIZE", AttributeType.TYPE_BLACK),
        new StringType("MOZVISUALSCROLL", AttributeType.TYPE_BLACK),
        new StringType("MUTE", AttributeType.TYPE_BLACK),
        new StringType("NAVIGATE", AttributeType.TYPE_BLACK),
        new StringType("NAVIGATEERROR", AttributeType.TYPE_BLACK),
        new StringType("NAVIGATESUCCESS", AttributeType.TYPE_BLACK),
        new StringType("NEGOTIATIONNEEDED", AttributeType.TYPE_BLACK),
        new StringType("NEXTTRACK", AttributeType.TYPE_BLACK),
        new StringType("NOMATCH", AttributeType.TYPE_BLACK),
        new StringType("NOTIFICATIONCLICK", AttributeType.TYPE_BLACK),
        new StringType("NOTIFICATIONCLOSE", AttributeType.TYPE_BLACK),
        new StringType("NOUPDATE", AttributeType.TYPE_BLACK),
        new StringType("OBSOLETE", AttributeType.TYPE_BLACK),
        new StringType("OFFLINE", AttributeType.TYPE_BLACK),
        new StringType("ONLINE", AttributeType.TYPE_BLACK),
        new StringType("OPEN", AttributeType.TYPE_BLACK),
        new StringType("ORIENTATIONCHANGE", AttributeType.TYPE_BLACK),
        new StringType("OVERFLOWCHANGED", AttributeType.TYPE_BLACK),
        new StringType("OVERSCROLL", AttributeType.TYPE_BLACK),
        new StringType("PAGEHIDE", AttributeType.TYPE_BLACK),
        new StringType("PAGEREVEAL", AttributeType.TYPE_BLACK),
        new StringType("PAGESHOW", AttributeType.TYPE_BLACK),
        new StringType("PAGESWAP", AttributeType.TYPE_BLACK),
        new StringType("PASTE", AttributeType.TYPE_BLACK),
        new StringType("PAUSE", AttributeType.TYPE_BLACK),
        new StringType("PAYERDETAILCHANGE", AttributeType.TYPE_BLACK),
        new StringType("PAYMENTAUTHORIZED", AttributeType.TYPE_BLACK),
        new StringType("PAYMENTMETHODCHANGE", AttributeType.TYPE_BLACK),
        new StringType("PAYMENTMETHODSELECTED", AttributeType.TYPE_BLACK),
        new StringType("PLAY", AttributeType.TYPE_BLACK),
        new StringType("PLAYING", AttributeType.TYPE_BLACK),
        new StringType("POINTERAUXCLICK", AttributeType.TYPE_BLACK),
        new StringType("POINTERCANCEL", AttributeType.TYPE_BLACK),
        new StringType("POINTERCLICK", AttributeType.TYPE_BLACK),
        new StringType("POINTERDOWN", AttributeType.TYPE_BLACK),
        new StringType("POINTERENTER", AttributeType.TYPE_BLACK),
        new StringType("POINTERGOTCAPTURE", AttributeType.TYPE_BLACK),
        new StringType("POINTERLEAVE", AttributeType.TYPE_BLACK),
        new StringType("POINTERLOCKCHANGE", AttributeType.TYPE_BLACK),
        new StringType("POINTERLOCKERROR", AttributeType.TYPE_BLACK),
        new StringType("POINTERLOSTCAPTURE", AttributeType.TYPE_BLACK),
        new StringType("POINTERMOVE", AttributeType.TYPE_BLACK),
        new StringType("POINTEROUT", AttributeType.TYPE_BLACK),
        new StringType("POINTEROVER", AttributeType.TYPE_BLACK),
        new StringType("POINTERRAWUPDATE", AttributeType.TYPE_BLACK),
        new StringType("POINTERUP", AttributeType.TYPE_BLACK),
        new StringType("POPSTATE", AttributeType.TYPE_BLACK),
        new StringType("PRESSTAPGESTURE", AttributeType.TYPE_BLACK),
        new StringType("PREVIOUSTRACK", AttributeType.TYPE_BLACK),
        new StringType("PROPERTYCHANGE", AttributeType.TYPE_BLACK),
        new StringType("PROCESSORERROR", AttributeType.TYPE_BLACK),
        new StringType("PROGRESS", AttributeType.TYPE_BLACK),
        new StringType("PUSH", AttributeType.TYPE_BLACK),
        new StringType("PUSHNOTIFICATION", AttributeType.TYPE_BLACK),
        new StringType("PUSHSUBSCRIPTIONCHANGE", AttributeType.TYPE_BLACK),
        new StringType("QUALITYCHANGE", AttributeType.TYPE_BLACK),
        new StringType("RATECHANGE", AttributeType.TYPE_BLACK),
        new StringType("READYSTATECHANGE", AttributeType.TYPE_BLACK),
        new StringType("REDRAW", AttributeType.TYPE_BLACK),
        new StringType("REJECTIONHANDLED", AttributeType.TYPE_BLACK),
        new StringType("RELEASE", AttributeType.TYPE_BLACK),
        new StringType("REMOVE", AttributeType.TYPE_BLACK),
        new StringType("REMOVESOURCEBUFFER", AttributeType.TYPE_BLACK),
        new StringType("REMOVESTREAM", AttributeType.TYPE_BLACK),
        new StringType("REMOVETRACK", AttributeType.TYPE_BLACK),
        new StringType("REPEAT", AttributeType.TYPE_BLACK),
        new StringType("REPEATEVENT", AttributeType.TYPE_BLACK),
        new StringType("RESET", AttributeType.TYPE_BLACK),
        new StringType("RESIZE", AttributeType.TYPE_BLACK),
        new StringType("RESOURCETIMINGBUFFERFULL", AttributeType.TYPE_BLACK),
        new StringType("RESULT", AttributeType.TYPE_BLACK),
        new StringType("RESUME", AttributeType.TYPE_BLACK),
        new StringType("ROTATEGESTURE", AttributeType.TYPE_BLACK),
        new StringType("ROTATEGESTURESTART", AttributeType.TYPE_BLACK),
        new StringType("ROTATEGESTUREUPDATE", AttributeType.TYPE_BLACK),
        new StringType("RTCTRANSFORM", AttributeType.TYPE_BLACK),
        new StringType("SCROLL", AttributeType.TYPE_BLACK),
        new StringType("SCROLLEDAREACHANGED", AttributeType.TYPE_BLACK),
        new StringType("SCROLLEND", AttributeType.TYPE_BLACK),
        new StringType("SCROLLPORTOVERFLOW", AttributeType.TYPE_BLACK),
        new StringType("SCROLLPORTUNDERFLOW", AttributeType.TYPE_BLACK),
        new StringType("SCROLLSNAPCHANGE", AttributeType.TYPE_BLACK),
        new StringType("SCROLLSNAPCHANGING", AttributeType.TYPE_BLACK),
        new StringType("SEARCH", AttributeType.TYPE_BLACK),
        new StringType("SECURITYPOLICYVIOLATION", AttributeType.TYPE_BLACK),
        new StringType("SEEKED", AttributeType.TYPE_BLACK),
        new StringType("SEEKING", AttributeType.TYPE_BLACK),
        new StringType("SELECT", AttributeType.TYPE_BLACK),
        new StringType("SELECTEDCANDIDATEPAIRCHANGE", AttributeType.TYPE_BLACK),
        new StringType("SELECTEND", AttributeType.TYPE_BLACK),
        new StringType("SELECTIONCHANGE", AttributeType.TYPE_BLACK),
        new StringType("SELECTSTART", AttributeType.TYPE_BLACK),
        new StringType("SHIPPINGADDRESSCHANGE", AttributeType.TYPE_BLACK),
        new StringType("SHIPPINGCONTACTSELECTED", AttributeType.TYPE_BLACK),
        new StringType("SHIPPINGMETHODSELECTED", AttributeType.TYPE_BLACK),
        new StringType("SHIPPINGOPTIONCHANGE", AttributeType.TYPE_BLACK),
        new StringType("SHOW", AttributeType.TYPE_BLACK),
        new StringType("SIGNALINGSTATECHANGE", AttributeType.TYPE_BLACK),
        new StringType("SLOTCHANGE", AttributeType.TYPE_BLACK),
        new StringType("SMILBEGINEVENT", AttributeType.TYPE_BLACK),
        new StringType("SMILENDEVENT", AttributeType.TYPE_BLACK),
        new StringType("SMILREPEATEVENT", AttributeType.TYPE_BLACK),
        new StringType("SORT", AttributeType.TYPE_BLACK),
        new StringType("SOUNDEND", AttributeType.TYPE_BLACK),
        new StringType("SOUNDSTART", AttributeType.TYPE_BLACK),
        new StringType("SOURCECLOSE", AttributeType.TYPE_BLACK),
        new StringType("SOURCEENDED", AttributeType.TYPE_BLACK),
        new StringType("SOURCEOPEN", AttributeType.TYPE_BLACK),
        new StringType("SPEECHEND", AttributeType.TYPE_BLACK),
        new StringType("SPEECHSTART", AttributeType.TYPE_BLACK),
        new StringType("SQUEEZE", AttributeType.TYPE_BLACK),
        new StringType("SQUEEZEEND", AttributeType.TYPE_BLACK),
        new StringType("SQUEEZESTART", AttributeType.TYPE_BLACK),
        new StringType("STALLED", AttributeType.TYPE_BLACK),
        new StringType("START", AttributeType.TYPE_BLACK),
        new StringType("STARTED", AttributeType.TYPE_BLACK),
        new StringType("STARTSTREAMING", AttributeType.TYPE_BLACK),
        new StringType("STATECHANGE", AttributeType.TYPE_BLACK),
        new StringType("STOP", AttributeType.TYPE_BLACK),
        new StringType("STORAGE", AttributeType.TYPE_BLACK),
        new StringType("SUBMIT", AttributeType.TYPE_BLACK),
        new StringType("SVGLOAD", AttributeType.TYPE_BLACK),
        new StringType("SVGSCROLL", AttributeType.TYPE_BLACK),
        new StringType("SWIPEGESTURE", AttributeType.TYPE_BLACK),
        new StringType("SWIPEGESTUREEND", AttributeType.TYPE_BLACK),
        new StringType("SWIPEGESTUREMAYSTART", AttributeType.TYPE_BLACK),
        new StringType("SWIPEGESTURESTART", AttributeType.TYPE_BLACK),
        new StringType("SWIPEGESTUREUPDATE", AttributeType.TYPE_BLACK),
        new StringType("SUCCESS", AttributeType.TYPE_BLACK),
        new StringType("SUSPEND", AttributeType.TYPE_BLACK),
        new StringType("TAPGESTURE", AttributeType.TYPE_BLACK),
        new StringType("TEXTINPUT", AttributeType.TYPE_BLACK),
        new StringType("TIMEOUT", AttributeType.TYPE_BLACK),
        new StringType("TIMEUPDATE", AttributeType.TYPE_BLACK),
        new StringType("TOGGLE", AttributeType.TYPE_BLACK),
        new StringType("TONECHANGE", AttributeType.TYPE_BLACK),
        new StringType("TOUCHCANCEL", AttributeType.TYPE_BLACK),
        new StringType("TOUCHEND", AttributeType.TYPE_BLACK),
        new StringType("TOUCHFORCECHANGE", AttributeType.TYPE_BLACK),
        new StringType("TOUCHMOVE", AttributeType.TYPE_BLACK),
        new StringType("TOUCHSTART", AttributeType.TYPE_BLACK),
        new StringType("TRACK", AttributeType.TYPE_BLACK),
        new StringType("TRANSITIONCANCEL", AttributeType.TYPE_BLACK),
        new StringType("TRANSITIONEND", AttributeType.TYPE_BLACK),
        new StringType("TRANSITIONRUN", AttributeType.TYPE_BLACK),
        new StringType("TRANSITIONSTART", AttributeType.TYPE_BLACK),
        new StringType("UNCAPTUREDERROR", AttributeType.TYPE_BLACK),
        new StringType("UNHANDLEDREJECTION", AttributeType.TYPE_BLACK),
        new StringType("UNIDENTIFIEDEVENT", AttributeType.TYPE_BLACK),
        new StringType("UNLOAD", AttributeType.TYPE_BLACK),
        new StringType("UNMUTE", AttributeType.TYPE_BLACK),
        new StringType("USERPROXIMITY", AttributeType.TYPE_BLACK),
        new StringType("UPDATE", AttributeType.TYPE_BLACK),
        new StringType("UPDATEEND", AttributeType.TYPE_BLACK),
        new StringType("UPDATEFOUND", AttributeType.TYPE_BLACK),
        new StringType("UPDATEREADY", AttributeType.TYPE_BLACK),
        new StringType("UPDATESTART", AttributeType.TYPE_BLACK),
        new StringType("UPGRADENEEDED", AttributeType.TYPE_BLACK),
        new StringType("VALIDATEMERCHANT", AttributeType.TYPE_BLACK),
        new StringType("VERSIONCHANGE", AttributeType.TYPE_BLACK),
        new StringType("VISIBILITYCHANGE", AttributeType.TYPE_BLACK),
        new StringType("VOICESCHANGED", AttributeType.TYPE_BLACK),
        new StringType("VOLUMECHANGE", AttributeType.TYPE_BLACK),
        new StringType("VRDISPLAYACTIVATE", AttributeType.TYPE_BLACK),
        new StringType("VRDISPLAYCONNECT", AttributeType.TYPE_BLACK),
        new StringType("VRDISPLAYDEACTIVATE", AttributeType.TYPE_BLACK),
        new StringType("VRDISPLAYDISCONNECT", AttributeType.TYPE_BLACK),
        new StringType("VRDISPLAYPRESENTCHANGE", AttributeType.TYPE_BLACK),
        new StringType("WAITING", AttributeType.TYPE_BLACK),
        new StringType("WAITINGFORKEY", AttributeType.TYPE_BLACK),
        new StringType("WEBGLCONTEXTCREATIONERROR", AttributeType.TYPE_BLACK),
        new StringType("WEBGLCONTEXTLOST", AttributeType.TYPE_BLACK),
        new StringType("WEBGLCONTEXTRESTORED", AttributeType.TYPE_BLACK),
        new StringType("WEBKITANIMATIONEND", AttributeType.TYPE_BLACK),
        new StringType("WEBKITANIMATIONITERATION", AttributeType.TYPE_BLACK),
        new StringType("WEBKITANIMATIONSTART", AttributeType.TYPE_BLACK),
        new StringType("WEBKITASSOCIATEFORMCONTROLS", AttributeType.TYPE_BLACK),
        new StringType("WEBKITAUTOFILLREQUEST", AttributeType.TYPE_BLACK),
        new StringType("WEBKITBEFORETEXTINSERTED", AttributeType.TYPE_BLACK),
        new StringType("WEBKITBEGINFULLSCREEN", AttributeType.TYPE_BLACK),
        new StringType("WEBKITCURRENTPLAYBACKTARGETISWIRELESSCHANGED", AttributeType.TYPE_BLACK),
        new StringType("WEBKITENDFULLSCREEN", AttributeType.TYPE_BLACK),
        new StringType("WEBKITFULLSCREENCHANGE", AttributeType.TYPE_BLACK),
        new StringType("WEBKITFULLSCREENERROR", AttributeType.TYPE_BLACK),
        new StringType("WEBKITKEYADDED", AttributeType.TYPE_BLACK),
        new StringType("WEBKITKEYERROR", AttributeType.TYPE_BLACK),
        new StringType("WEBKITKEYMESSAGE", AttributeType.TYPE_BLACK),
        new StringType("WEBKITMEDIASESSIONMETADATACHANGED", AttributeType.TYPE_BLACK),
        new StringType("WEBKITMOUSEFORCECHANGED", AttributeType.TYPE_BLACK),
        new StringType("WEBKITMOUSEFORCEDOWN", AttributeType.TYPE_BLACK),
        new StringType("WEBKITMOUSEFORCEUP", AttributeType.TYPE_BLACK),
        new StringType("WEBKITMOUSEFORCEWILLBEGIN", AttributeType.TYPE_BLACK),
        new StringType("WEBKITNEEDKEY", AttributeType.TYPE_BLACK),
        new StringType("WEBKITNETWORKINFOCHANGE", AttributeType.TYPE_BLACK),
        new StringType("WEBKITPLAYBACKTARGETAVAILABILITYCHANGED", AttributeType.TYPE_BLACK),
        new StringType("WEBKITPRESENTATIONMODECHANGED", AttributeType.TYPE_BLACK),
        new StringType("WEBKITREMOVESOURCEBUFFER", AttributeType.TYPE_BLACK),
        new StringType("WEBKITSHADOWROOTATTACHED", AttributeType.TYPE_BLACK),
        new StringType("WEBKITSOURCECLOSE", AttributeType.TYPE_BLACK),
        new StringType("WEBKITSOURCEENDED", AttributeType.TYPE_BLACK),
        new StringType("WEBKITSOURCEOPEN", AttributeType.TYPE_BLACK),
        new StringType("WEBKITTRANSITIONEND", AttributeType.TYPE_BLACK),
        new StringType("WHEEL", AttributeType.TYPE_BLACK),
        new StringType("WRITE", AttributeType.TYPE_BLACK),
        new StringType("WRITEEND", AttributeType.TYPE_BLACK),
        new StringType("WRITESTART", AttributeType.TYPE_BLACK),
        new StringType("XULBROADCAST", AttributeType.TYPE_BLACK),
        new StringType("XULCOMMANDUPDATE", AttributeType.TYPE_BLACK),
        new StringType("XULPOPUPHIDDEN", AttributeType.TYPE_BLACK),
        new StringType("XULPOPUPHIDING", AttributeType.TYPE_BLACK),
        new StringType("XULPOPUPSHOWING", AttributeType.TYPE_BLACK),
        new StringType("XULPOPUPSHOWN", AttributeType.TYPE_BLACK),
        new StringType("XULSYSTEMSTATUSBARCLICK", AttributeType.TYPE_BLACK),
        new StringType("ZOOM", AttributeType.TYPE_BLACK),
        new StringType(null, AttributeType.TYPE_NONE)
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
     * Case-insensitive string comparison with offset support.
     * This variant allows comparing starting from an offset in string b,
     * avoiding the need to create substring allocations.
     */
    private static int cstrcasecmp_with_null_offset(String a, String b, int bOffset, int n) {
        char ca;
        char cb;
        int aIdx = 0;
        int bIdx = bOffset;

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
        return htmlencode_startswith_offset(a, b, 0, n);
    }

    /**
     * Checks if string b (starting at bStartOffset) starts with string a, considering HTML encoding.
     * This variant accepts an offset to avoid substring allocations.
     */
    private static boolean htmlencode_startswith_offset(String a, String b, int bStartOffset, int n) {
        int bOffset = bStartOffset;
        int aOffset = 0;
        int aLen = a.length();
        int cb;
        boolean first = true;

        while (n > 0 && bOffset < b.length()) {
            if (aOffset >= aLen) {
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

            if (a.charAt(aOffset) != (char) cb) {
                return false;
            }
            aOffset++;
        }

        return aOffset >= aLen;
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
     * For on* attributes, validates against the BLACKATTREVENT list.
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

            // JavaScript on.* event handlers
            if ((c0 == 'o' || c0 == 'O') && (c1 == 'n' || c1 == 'N')) {
                // Start comparing from the third char (skip "on") using offset to avoid substring
                int sWithoutOnLen = len - 2;

                for (StringType black : BLACKATTREVENT) {
                    if (black.name == null) break;
                    int blackNameLen = black.name.length();
                    // Determine the maximum length to compare
                    int maxLen = Math.min(sWithoutOnLen, blackNameLen);
                    if (cstrcasecmp_with_null_offset(black.name, s, 2, maxLen) == 0) {
                        return black.atype;
                    }
                }
            }

            // XMLNS can be used to create arbitrary tags
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

        // Use offset version to avoid substring allocation
        if (htmlencode_startswith_offset(data_url, s, offset, len)) {
            return true;
        }

        if (htmlencode_startswith_offset(viewsource_url, s, offset, len)) {
            return true;
        }

        if (htmlencode_startswith_offset(javascript_url, s, offset, len)) {
            return true;
        }

        if (htmlencode_startswith_offset(vbscript_url, s, offset, len)) {
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
                if (is_black_tag(h5.getTokenString(), h5.token_len)) {
                    return true;
                }
            } else if (h5.token_type == Html5Type.ATTR_NAME) {
                attr = is_black_attr(h5.getTokenString(), h5.token_len);
            } else if (h5.token_type == Html5Type.ATTR_VALUE) {
                switch (attr) {
                    case TYPE_NONE:
                        break;
                    case TYPE_BLACK:
                        return true;
                    case TYPE_ATTR_URL:
                        if (is_black_url(h5.getTokenString(), h5.token_len)) {
                            return true;
                        }
                        break;
                    case TYPE_STYLE:
                        return true;
                    case TYPE_ATTR_INDIRECT:
                        if (is_black_attr(h5.getTokenString(), h5.token_len) != AttributeType.TYPE_NONE) {
                            return true;
                        }
                        break;
                }
                attr = AttributeType.TYPE_NONE;
            } else if (h5.token_type == Html5Type.TAG_COMMENT) {
                if (h5.tokenIndexOf('`') != -1) {
                    return true;
                }

                if (h5.token_len > 3) {
                    char c0 = h5.getTokenCharAt(0);
                    char c1 = h5.getTokenCharAt(1);
                    char c2 = h5.getTokenCharAt(2);
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
                    if (cstrcasecmp_with_null("IMPORT", h5.getTokenString(), 6) == 0) {
                        return true;
                    }

                    if (cstrcasecmp_with_null("ENTITY", h5.getTokenString(), 6) == 0) {
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
