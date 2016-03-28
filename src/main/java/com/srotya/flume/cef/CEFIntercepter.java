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

import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.flume.Event;
import org.apache.flume.interceptor.Interceptor;

public class CEFIntercepter implements Interceptor {

	public static final String SEVERITY = "severity";
	public static final String NAME = "name";
	public static final String SIGNATURE = "signature";
	public static final String VERSION = "version";
	public static final String PRODUCT = "product";
	public static final String VENDOR = "vendor";
	public static final String CEF_VERSION = "cefVersion";
	private static final String cefRegex = "(?<!\\\\)\\|";
	private static final String cefExtension = "(?<!\\\\)=";
	private static final Pattern cefPattern = Pattern.compile(cefRegex);
	private static final Pattern extensionPattern = Pattern.compile(cefExtension);

	@Override
	public void close() {
	}

	@Override
	public void initialize() {
	}

	@Override
	public Event intercept(Event event) {
		if(event.getBody()!=null) {
			String cefBody = new String(event.getBody(), Charset.forName("utf-8"));
			try{
				parseToCEFOptimized(event.getHeaders(), cefBody);
			}catch(Exception e) {
				return null;
			}
		}
		return event;
	}

	@Override
	public List<Event> intercept(List<Event> events) {
		for (Iterator<Event> iterator = events.iterator(); iterator.hasNext();) {
			Event event = iterator.next();
			if (intercept(event) == null) {
				iterator.remove();
			}
		}
		return events;
	}

	/**
	 * Parse CEF body to Flume {@link Event} headers
	 * @param headers
	 * @param cefBody
	 */
	public static void parseToCEFOptimized(Map<String, String> headers, String cefBody) {
		Matcher m = cefPattern.matcher(cefBody);
		int counter = 0, index = 0;
		while (counter < 7 && m.find()) {
			String val = cefBody.substring(index, m.start());
			switch (counter) {
			case 0:
				headers.put(CEF_VERSION, ""+val.charAt(val.length() - 1));
				break;
			case 1:
				headers.put(VENDOR, val);
				break;
			case 2:
				headers.put(PRODUCT, val);
				break;
			case 3:
				headers.put(VERSION, val);
				break;
			case 4:
				headers.put(SIGNATURE, val);
				break;
			case 5:
				headers.put(NAME, val);
				break;
			case 6:
				headers.put(SEVERITY, String.valueOf(Integer.parseInt(val)));
				break;
			}
			index = m.end();
			counter++;
		}
		// process extensions
		String ext = cefBody.substring(index);
		m = extensionPattern.matcher(ext);
		index = 0;
		String key = null;
		String value = null;
		while (m.find()) {
			if (key == null) {
				key = ext.substring(index, m.start());
				index = m.end();
				if (!m.find()) {
					break;
				}
			}
			value = ext.substring(index, m.start());
			index = m.end();
			int v = value.lastIndexOf(" ");
			if (v > 0) {
				String temp = value.substring(0, v).trim();
				headers.put(key, temp);
				key = value.substring(v).trim();
			}
		}
		value = ext.substring(index);
		headers.put(key, value);
	}

}