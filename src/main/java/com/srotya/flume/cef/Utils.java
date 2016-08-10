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

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Contains the core CEF parser
 * 
 * @author ambudsharma
 */
public class Utils {

	public static final String SEVERITY = "severity";
	public static final String NAME = "name";
	public static final String SIGNATURE = "signature";
	public static final String VERSION = "version";
	public static final String PRODUCT = "product";
	public static final String VENDOR = "vendor";
	public static final String CEF_VERSION = "cefVersion";
	static final String cefRegex = "(?<!\\\\)\\|";
	static final String cefExtension = "(?<!\\\\)=";
	static final Pattern cefPattern = Pattern.compile(cefRegex);
	static final Pattern extensionPattern = Pattern.compile(cefExtension);
	static ParseException INVALID_VALUE_EXCEPTION = new ParseException(
			"Invalid value null exception, event is not correctly formatted");
	static ParseException INVALID_DATA_EXCEPTION = new ParseException("Invalid data, event is not correctly formatted");

	/**
	 * Parse CEF body to {@link Map} of headers
	 * 
	 * @param headers
	 * @param cefBody
	 * @throws ParseException
	 */
	public static void parseToCEFOptimized(Map<String, String> headers, String cefBody) throws ParseException {
		try {
			Matcher m = cefPattern.matcher(cefBody);
			int counter = 0, index = 0;
			while (counter < 7 && m.find()) {
				String val = cefBody.substring(index, m.start());
				switch (counter) {
				case 0:
					headers.put(CEF_VERSION, "" + val.charAt(val.length() - 1));
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
			if (headers.size() < 6) {
				throw INVALID_DATA_EXCEPTION;
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
					if (temp == null || temp.isEmpty()) {
						throw INVALID_VALUE_EXCEPTION;
					}
					headers.put(key, temp);
					key = value.substring(v).trim();
				} else {
					throw INVALID_VALUE_EXCEPTION;
				}
			}
			value = ext.substring(index);
			if (value == null || value.isEmpty()) {
				throw INVALID_VALUE_EXCEPTION;
			}
			headers.put(key, value);
		} catch (ParseException e) {
			throw e;
		} catch (Exception e) {
			throw new ParseException("CEF Parsing failed", e);
		}
	}

}
