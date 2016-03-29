# CEF (Common Event Format)
Common Event Format Interceptor for Apache Flume. Use this interceptor to parse and convert CEF payloads in Syslog to Flume Event headers.

Common Event Format commonly known as CEF (pronounced sef), is the defacto format of HP ArcSight Logging and Security monitoring product family (including Loggers and ESM), you can read more about CEF here: https://www.protect724.hpe.com/docs/DOC-1072. It's also widely adopted by a few security products making parsing it critical to interpreting the logs and making sense out of them. CEF is usually transmitted over Syslog protocol as a payload.

This parser is a available in form of an Apache Flume Interceptor (https://flume.apache.org/FlumeUserGuide.html#flume-interceptors) and is best used in conjunction with SyslogSources (TCP / UDP) however you can use it with any other Flume Source as long as the byte[] body of emitted from the Flume Source is CEF only.

# Compliance
This version of CEF Interceptor is complaint with Apache Flume 1.6.0

# How to use?
The parser has no external dependencies so all you need to do is download the latest JAR from Maven Central to the lib folder of your Flume installation and configure the interceptor as shown below and start sending some CEF logs.


# Bugs and Issues?
Please report bugs via github issues.
