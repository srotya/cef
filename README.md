# CEF (Common Event Format)
Common Event Format Interceptor for Apache Flume. Use this interceptor to parse and convert CEF payloads in Syslog to Flume Event headers.

Common Event Format commonly known as CEF (pronounced sef), is the defacto format of HP ArcSight Logging and Security monitoring product family (including Loggers and ESM), you can read more about CEF here: https://www.protect724.hpe.com/docs/DOC-1072. It's also widely adopted by a few security products making parsing it critical to interpreting the logs and making sense out of them. CEF is usually transmitted over Syslog protocol as a payload.

This parser is a available in form of an Apache Flume Interceptor (https://flume.apache.org/FlumeUserGuide.html#flume-interceptors) and is best used in conjunction with SyslogSources (TCP / UDP) however you can use it with any other Flume Source as long as the byte[] body of emitted from the Flume Source is CEF only.

Note: This parser currently doesn't validate events beyond CEF Prefix and Invalid extensions. It currently doesn't check dictionary validation or data type validation for dictionary items. This is partly because Flume headers are String valued therefore type conversion has no benefit and as well as for performance reasons.

# Compliance
This version of CEF Interceptor is complaint with Apache Flume 1.6.0

# How to use?
Please download the published artifact from Maven Central, 0.0.10 or greater is current stable version.

```xml
<dependency>
    <groupId>com.srotya.flume</groupId>
    <artifactId>cef</artifactId>
    <version>0.0.11</version>
</dependency>
```

The parser has no external dependencies so all you need to do is download the latest JAR from Maven Central to the lib folder of your Flume installation and configure the interceptor as shown below and start sending some CEF logs:

agent.sources = syslog

agent.channels = memoryChannel

agent.sinks = loggerSink

agent.sources.syslog.type = syslogtcp

agent.sources.syslog.port = 1514

agent.sources.syslog.interceptors = cef

agent.sources.syslog.interceptors.cef.type = com.srotya.flume.cef.CEFInterceptor$Builder

agent.sources.syslog.channels = memoryChannel

agent.sinks.loggerSink.type = logger

agent.sinks.loggerSink.channel = memoryChannel

agent.channels.memoryChannel.type = memory

agent.channels.memoryChannel.capacity = 100

# Bugs and Issues?
Please report bugs via github issues.
