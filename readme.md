# libinjection-jvm

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Maven Central](https://img.shields.io/maven-central/v/com.cloud.apim/libinjection-jvm.svg)](https://search.maven.org/artifact/com.cloud.apim/libinjection-jvm)

Java port of [libinjection](https://github.com/client9/libinjection) - SQL / SQLI / XSS tokenizer parser analyzer for detecting injection attacks.

This is a faithful port of the C implementation to Java, maintaining the same detection capabilities and fingerprinting system.

## Features

- **SQLi Detection**: Detects SQL injection attempts using fingerprinting and pattern matching
- **XSS Detection**: Detects Cross-Site Scripting (XSS) attacks in HTML5 contexts
- **Multi-dialect Support**: Handles ANSI SQL and MySQL syntax differences
- **9352+ Fingerprints**: Comprehensive database of known SQLi attack patterns
- **Zero Dependencies**: No external runtime dependencies (only JUnit for tests)
- **Java 8+**: Compatible with Java 8 and above

## Installation

### Maven

```xml
<dependency>
    <groupId>com.cloud.apim</groupId>
    <artifactId>libinjection-jvm</artifactId>
    <version>3.9.2</version>
</dependency>
```

### Gradle

```gradle
implementation 'com.cloud.apim:libinjection-jvm:3.9.2'
```

## Usage

### SQLi Detection

```java
import com.cloud.apim.libinjection.LibInjection;

public class Example {
    public static void main(String[] args) {
        String input = "-1' and 1=1 union/* foo */select load_file('/etc/passwd')--";
        
        boolean isSqli = LibInjection.isSQLi(input);
        
        if (isSqli) {
            System.out.println("SQLi detected!");
        }
    }
}
```

### XSS Detection

```java
import com.cloud.apim.libinjection.LibInjection;

public class Example {
    public static void main(String[] args) {
        String input = "<script>alert('xss')</script>";
        
        boolean isXss = LibInjection.isXSS(input);
        
        if (isXss) {
            System.out.println("XSS detected!");
        }
    }
}
```

## How It Works

### SQLi Detection

The library uses a multi-step approach to detect SQL injection:

1. **Tokenization**: The input is parsed into SQL tokens (keywords, operators, strings, numbers, etc.)
2. **Folding**: Tokens are reduced and normalized to create a simplified representation
3. **Fingerprinting**: A fingerprint pattern is generated from the token sequence
4. **Pattern Matching**: The fingerprint is compared against a database of known SQLi patterns
5. **Context Testing**: The input is tested in multiple contexts (no quotes, single quotes, double quotes)

Example fingerprints:
- `s&1UE` - String, logic operator, number, UNION, expression
- `1oc` - Number, operator, comment
- `1&1` - Number, logic operator, number

### XSS Detection

The XSS detector analyzes HTML5 contexts and identifies potentially dangerous patterns that could lead to script execution.

## Implementation Notes

This Java port intentionally follows the C implementation closely rather than using idiomatic Java patterns. This design choice:

- Makes it easier to track changes from the upstream C version
- Facilitates debugging by allowing direct comparison with the C code
- Maintains the same performance characteristics and behavior

## Building from Source

```bash
# Clone the repository
git clone https://github.com/cloud-apim/libinjection-jvm.git
cd libinjection-jvm/java

# Build with Maven
mvn clean install

# Run tests
mvn test

# Generate sources and javadoc
mvn source:jar javadoc:jar
```

## Version Information

This port follows the versioning of the original libinjection C library.

**Current version: 3.9.2**

Version format: `major.minor.point`

- **Major**: Significant changes to the API and/or fingerprint format
- **Minor**: Code changes (logic, optimization, refactoring)
- **Point**: Data-only changes (fingerprint updates)

## Performance Considerations

- **Zero allocation**: The detection process minimizes object allocation
- **Fast pattern matching**: Uses binary search for keyword lookup
- **Efficient tokenization**: Single-pass parsing with minimal backtracking
- **Thread-safe**: All public methods are stateless and thread-safe

## Comparison with C Implementation

| Feature | C Version | Java Version |
|---------|-----------|--------------|
| SQLi Detection | ✅ | ✅ |
| XSS Detection | ✅ | ✅ |
| Fingerprint Database | 9352 patterns | 9352 patterns |
| Multi-context Testing | ✅ | ✅ |
| MySQL/ANSI Support | ✅ | ✅ |
| Dependencies | None | None (runtime) |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

When contributing:
1. Maintain compatibility with the C implementation
2. Add tests for new features
3. Follow the existing code style (C-like, not idiomatic Java)
4. Update documentation as needed

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](../COPYING) file for details.

The original libinjection C library is:
- Copyright (c) 2012-2016 Nick Galbreath
- Licensed under BSD 3-Clause License

## Credits

- **Original Author**: [Nick Galbreath](https://github.com/client9) - C implementation
- **Java Port**: [Mathieu Ancelin](https://github.com/mathieuancelin) - Cloud APIM

## Links

- **Original C Library**: https://github.com/client9/libinjection
- **Documentation**: https://libinjection.client9.com/
- **Issue Tracker**: https://github.com/cloud-apim/libinjection-jvm/issues
- **Maven Central**: https://search.maven.org/artifact/com.cloud.apim/libinjection-jvm

## Related Projects

- [libinjection (C)](https://github.com/client9/libinjection) - Original C implementation
- [libinjection-php](https://github.com/client9/libinjection/tree/master/php) - PHP extension
- [libinjection-python](https://github.com/client9/libinjection/tree/master/python) - Python bindings
- [libinjection-lua](https://github.com/client9/libinjection/tree/master/lua) - Lua bindings

## Support

For questions, issues, or feature requests, please use the [GitHub Issues](https://github.com/cloud-apim/libinjection-jvm/issues) page.
