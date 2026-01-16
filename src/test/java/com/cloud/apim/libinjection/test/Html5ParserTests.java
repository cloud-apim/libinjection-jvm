package com.cloud.apim.libinjection.test;

import com.cloud.apim.libinjection.impl.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class Html5ParserTests {

    private final String testName;
    private final String input;
    private final String expected;

    public Html5ParserTests(String testName, String input, String expected) {
        this.testName = testName;
        this.input = input;
        this.expected = expected;
    }

    @Parameters(name = "{0}")
    public static Collection<Object[]> data() throws IOException {
        List<Object[]> testCases = new ArrayList<>();

        // Try multiple paths to find the test data
        Path testsDir = null;
        String[] possiblePaths = {
            "test-data/libinjection-go/tests",
            "../test-data/libinjection-go/tests",
            "libinjection-jvm/test-data/libinjection-go/tests"
        };

        for (String path : possiblePaths) {
            Path p = Paths.get(path);
            if (Files.exists(p)) {
                testsDir = p;
                break;
            }
        }

        if (testsDir == null) {
            System.err.println("Warning: test-data directory not found, skipping HTML5 parser tests");
            System.err.println("Working directory: " + Paths.get(".").toAbsolutePath());
            return testCases;
        }

        List<Path> html5Files = Files.list(testsDir)
            .filter(p -> p.getFileName().toString().contains("-html5-"))
            .sorted()
            .collect(Collectors.toList());

        for (Path file : html5Files) {
            Map<String, String> data = readTestData(file);
            testCases.add(new Object[]{
                file.getFileName().toString(),
                data.get("--INPUT--"),
                data.get("--EXPECTED--")
            });
        }

        return testCases;
    }

    @Test
    public void testHtml5Parser() {
        String actual = runHtml5Parser(input != null ? input : "").trim();
        String expectedValue = expected != null ? expected.trim() : "";
        assertEquals("File: " + testName + "\nInput: " + input, expectedValue, actual);
    }

    private String runHtml5Parser(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        H5State h5 = new H5State();
        LibInjectionHTML5.libinjection_h5_init(h5, input, input.length(), Html5Flags.DATA_STATE);

        StringBuilder result = new StringBuilder();
        while (LibInjectionHTML5.libinjection_h5_next(h5) != 0) {
            if (result.length() > 0) {
                result.append("\n");
            }
            result.append(h5TypeToString(h5.token_type));
            result.append(",");
            result.append(h5.token_len);
            result.append(",");
            result.append(h5.token_start.substring(0, h5.token_len));
        }

        return result.toString();
    }

    private static String h5TypeToString(Html5Type type) {
        switch (type) {
            case DATA_TEXT: return "DATA_TEXT";
            case TAG_NAME_OPEN: return "TAG_NAME_OPEN";
            case TAG_NAME_CLOSE: return "TAG_NAME_CLOSE";
            case TAG_NAME_SELFCLOSE: return "TAG_NAME_SELFCLOSE";
            case TAG_DATA: return "TAG_DATA";
            case TAG_CLOSE: return "TAG_CLOSE";
            case ATTR_NAME: return "ATTR_NAME";
            case ATTR_VALUE: return "ATTR_VALUE";
            case TAG_COMMENT: return "TAG_COMMENT";
            case DOCTYPE: return "DOCTYPE";
            default: return "";
        }
    }

    private static Map<String, String> readTestData(Path file) throws IOException {
        Map<String, String> data = new HashMap<>();
        String state = "";

        try (BufferedReader reader = Files.newBufferedReader(file)) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.equals("--TEST--") || trimmed.equals("--INPUT--") || trimmed.equals("--EXPECTED--")) {
                    state = trimmed;
                } else {
                    String current = data.getOrDefault(state, "");
                    if (!current.isEmpty()) {
                        current += "\n";
                    }
                    data.put(state, current + trimmed);
                }
            }
        }

        // Trim whitespace from all values
        data.replaceAll((k, v) -> v != null ? v.trim() : "");

        return data;
    }
}
