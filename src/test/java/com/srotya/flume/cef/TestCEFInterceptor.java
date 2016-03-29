/**
 * Copyright 2016 Ambud Sharma
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * 		http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.srotya.flume.cef;

import static org.junit.Assert.*;

import java.nio.charset.Charset;
import java.util.HashMap;

import org.apache.flume.Event;
import org.apache.flume.event.EventBuilder;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for CEF parser covering base cases
 * 
 * @author ambudsharma
 */
public class TestCEFInterceptor {
	
	private CEFInterceptor intercepter;
	
	@Before
	public void before() {
		intercepter = new CEFInterceptor();
	}

	@Test
	public void testSimpleCEFMessage() {
		String msg = "CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232";
		Event event = EventBuilder.withBody(msg, Charset.forName("utf-8"), new HashMap<>());
		if(intercepter.intercept(event)==null) {
			fail("Not parsed as a valid event");
		}
		assertEquals("0", event.getHeaders().get(CEFInterceptor.CEF_VERSION));
		assertEquals("security", event.getHeaders().get(CEFInterceptor.VENDOR));
		assertEquals("threatmanager", event.getHeaders().get(CEFInterceptor.PRODUCT));
		assertEquals("1.0", event.getHeaders().get(CEFInterceptor.VERSION));
		assertEquals("100", event.getHeaders().get(CEFInterceptor.SIGNATURE));
		assertEquals("worm successfully stopped", event.getHeaders().get(CEFInterceptor.NAME));
		assertEquals("10", event.getHeaders().get(CEFInterceptor.SEVERITY));
		
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
		assertEquals("0", event.getHeaders().get(CEFInterceptor.CEF_VERSION));
		assertEquals("security", event.getHeaders().get(CEFInterceptor.VENDOR));
		assertEquals("threatmanager", event.getHeaders().get(CEFInterceptor.PRODUCT));
		assertEquals("1.0", event.getHeaders().get(CEFInterceptor.VERSION));
		assertEquals("100", event.getHeaders().get(CEFInterceptor.SIGNATURE));
		assertEquals("detected a \\| in message", event.getHeaders().get(CEFInterceptor.NAME));
		assertEquals("10", event.getHeaders().get(CEFInterceptor.SEVERITY));
		
		assertEquals("10.0.0.1", event.getHeaders().get("src"));
		assertEquals("blocked a |", event.getHeaders().get("act"));
		assertEquals("1.1.1.1", event.getHeaders().get("dst"));
	}
	
	@Test
	public void testInValidPrefixField() {
		String msg = "CEF:0|security|threatmanager|1.0|100|detected a| in message|10|src=10.0.0.1 act=blocked a | dst=1.1.1.1";
		Event event = EventBuilder.withBody(msg, Charset.forName("utf-8"), new HashMap<>());
		if(intercepter.intercept(event)!=null) {
			fail("Parsed invalid event");
		}
	}
	
	@Test
	public void testComplexExtension() {
		String msg = "CEF:0|security|threatmanager|1.0|100|detected a = in message|10|src=10.0.0.1 act=blocked a \\= dst=1.1.1.1";
		Event event = EventBuilder.withBody(msg, Charset.forName("utf-8"), new HashMap<>());
		if(intercepter.intercept(event)==null) {
			fail("Not parsed as a valid event");
		}
		assertEquals("0", event.getHeaders().get(CEFInterceptor.CEF_VERSION));
		assertEquals("security", event.getHeaders().get(CEFInterceptor.VENDOR));
		assertEquals("threatmanager", event.getHeaders().get(CEFInterceptor.PRODUCT));
		assertEquals("1.0", event.getHeaders().get(CEFInterceptor.VERSION));
		assertEquals("100", event.getHeaders().get(CEFInterceptor.SIGNATURE));
		assertEquals("detected a = in message", event.getHeaders().get(CEFInterceptor.NAME));
		assertEquals("10", event.getHeaders().get(CEFInterceptor.SEVERITY));
		
		assertEquals("10.0.0.1", event.getHeaders().get("src"));
		assertEquals("blocked a \\=", event.getHeaders().get("act"));
		assertEquals("1.1.1.1", event.getHeaders().get("dst"));
	}
	
	@Test
	public void testBadExtension1() {
		String msg = "CEF:0|security|threatmanager|1.0|100|detected a = in message|10|src=10.0.0.1 act=blocked a \\= dst=";
		Event event = EventBuilder.withBody(msg, Charset.forName("utf-8"), new HashMap<>());
		if(intercepter.intercept(event)!=null) {
			fail("Parsed an invalid:"+event.getHeaders().get("dst"));
		}
	}
	
	@Test
	public void testBadExtension2() {
		String msg = "CEF:0|security|threatmanager|1.0|100|detected a = in message|10|src=10.0.0.1 act= dst=10";
		Event event = EventBuilder.withBody(msg, Charset.forName("utf-8"), new HashMap<>());
		if(intercepter.intercept(event)!=null) {
			fail("Parsed an invalid:"+event.getHeaders().get("act"));
		}
	}
	
}
