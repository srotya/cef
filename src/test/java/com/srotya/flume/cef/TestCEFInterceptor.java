package com.srotya.flume.cef;

import static org.junit.Assert.*;

import java.nio.charset.Charset;
import java.util.HashMap;

import org.apache.flume.Event;
import org.apache.flume.event.EventBuilder;
import org.junit.Before;
import org.junit.Test;

public class TestCEFInterceptor {
	
	private CEFIntercepter intercepter;
	
	@Before
	public void before() {
		intercepter = new CEFIntercepter();
	}

	@Test
	public void testSimpleCEFMessage() {
		String msg = "CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232";
		Event event = EventBuilder.withBody(msg, Charset.forName("utf-8"), new HashMap<>());
		if(intercepter.intercept(event)==null) {
			fail("Not parsed as a valid event");
		}
		assertEquals("0", event.getHeaders().get(CEFIntercepter.CEF_VERSION));
		assertEquals("security", event.getHeaders().get(CEFIntercepter.VENDOR));
		assertEquals("threatmanager", event.getHeaders().get(CEFIntercepter.PRODUCT));
		assertEquals("1.0", event.getHeaders().get(CEFIntercepter.VERSION));
		assertEquals("100", event.getHeaders().get(CEFIntercepter.SIGNATURE));
		assertEquals("worm successfully stopped", event.getHeaders().get(CEFIntercepter.NAME));
		assertEquals("10", event.getHeaders().get(CEFIntercepter.SEVERITY));
		
		assertEquals("10.0.0.1", event.getHeaders().get("src"));
		assertEquals("2.1.2.2", event.getHeaders().get("dst"));
		assertEquals("1232", event.getHeaders().get("spt"));
	}
	
	@Test
	public void testPipeInPrefixFields() {
		String msg = "CEF:0|security|threatmanager|1.0|100|detected a \\| in message|10|src=10.0.0.1 act=blocked a | dst=1.1.1.1";
		Event event = EventBuilder.withBody(msg, Charset.forName("utf-8"), new HashMap<>());
		if(intercepter.intercept(event)==null) {
			fail("Not parsed as a valid event");
		}
		assertEquals("0", event.getHeaders().get(CEFIntercepter.CEF_VERSION));
		assertEquals("security", event.getHeaders().get(CEFIntercepter.VENDOR));
		assertEquals("threatmanager", event.getHeaders().get(CEFIntercepter.PRODUCT));
		assertEquals("1.0", event.getHeaders().get(CEFIntercepter.VERSION));
		assertEquals("100", event.getHeaders().get(CEFIntercepter.SIGNATURE));
		assertEquals("detected a \\| in message", event.getHeaders().get(CEFIntercepter.NAME));
		assertEquals("10", event.getHeaders().get(CEFIntercepter.SEVERITY));
		
		assertEquals("10.0.0.1", event.getHeaders().get("src"));
		assertEquals("blocked a |", event.getHeaders().get("act"));
		assertEquals("1.1.1.1", event.getHeaders().get("dst"));
	}
	
	@Test
	public void testInValidPrefixField() {
		String msg = "CEF:0|security|threatmanager|1.0|100|detected a| in message|10|src=10.0.0.1 act=blocked a | dst=1.1.1.1";
		Event event = EventBuilder.withBody(msg, Charset.forName("utf-8"), new HashMap<>());
		if(intercepter.intercept(event)!=null) {
			fail("Not parsed as a valid event");
		}
	}
	
	@Test
	public void testComplexExtension() {
		String msg = "CEF:0|security|threatmanager|1.0|100|detected a = in message|10|src=10.0.0.1 act=blocked a \\= dst=1.1.1.1";
		Event event = EventBuilder.withBody(msg, Charset.forName("utf-8"), new HashMap<>());
		if(intercepter.intercept(event)==null) {
			fail("Not parsed as a valid event");
		}
		assertEquals("0", event.getHeaders().get(CEFIntercepter.CEF_VERSION));
		assertEquals("security", event.getHeaders().get(CEFIntercepter.VENDOR));
		assertEquals("threatmanager", event.getHeaders().get(CEFIntercepter.PRODUCT));
		assertEquals("1.0", event.getHeaders().get(CEFIntercepter.VERSION));
		assertEquals("100", event.getHeaders().get(CEFIntercepter.SIGNATURE));
		assertEquals("detected a = in message", event.getHeaders().get(CEFIntercepter.NAME));
		assertEquals("10", event.getHeaders().get(CEFIntercepter.SEVERITY));
		
		assertEquals("10.0.0.1", event.getHeaders().get("src"));
		assertEquals("blocked a \\=", event.getHeaders().get("act"));
		assertEquals("1.1.1.1", event.getHeaders().get("dst"));
	}
	
}
