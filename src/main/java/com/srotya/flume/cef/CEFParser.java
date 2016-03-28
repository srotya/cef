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

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CEFParser {
	
	private static final String cefRegex = "(?<!\\\\)\\|";
	private static final String cefExtension = "(?<!\\\\)=";
	private static final Pattern cefPattern = Pattern.compile(cefRegex);
	private static final Pattern extensionPattern = Pattern.compile(cefExtension);

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		long ts = System.currentTimeMillis();
		int loop = 10;
		String test = "CEF:0|security|threatmanager|1.0|100|detected a \\| in message|10|src=10.0.0.1 act=blocked a \\= and \\ dst=1.1.1.1 fileName=C:\\Program Files\\test.txt port=test";

		ts = System.currentTimeMillis();
		for (int i = 0; i < loop; i++) {
			CEFEvent event = parseToCEFOptimized(test);
			System.out.println(event);
		}
		System.out.println((System.currentTimeMillis() - ts) + " ms for " + loop + " calls");

	}

	public static CEFEvent parseToCEFOptimized(String event) {
		CEFEvent cef = new CEFEvent();
		Matcher m = cefPattern.matcher(event);
		int counter = 0, index = 0;
		while (counter < 7 && m.find()) {
			String val = event.substring(index, m.start());
			switch (counter) {
			case 0:
				cef.setCefVersion((byte) val.charAt(val.length() - 1));
				break;
			case 1:
				cef.setVendor(val);
				break;
			case 2:
				cef.setProduct(val);
				break;
			case 3:
				cef.setVersion(val);
				break;
			case 4:
				cef.setSignature(val);
				break;
			case 5:
				cef.setName(val);
				break;
			case 6:
				cef.setSeverity((byte) (Integer.parseInt(val)));
				break;
			}
			index = m.end();
			counter++;
		}
		// process extensions
		String ext = event.substring(index);
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
				cef.getExtensions().put(key, temp);
				key = value.substring(v).trim();
			}
		}
		value = ext.substring(index);
		cef.getExtensions().put(key, value);
		return cef;
	}

	public static class CEFEvent {

		private byte cefVersion;
		private String vendor;
		private String product;
		private String version;
		private String signature;
		private String name;
		private byte severity;
		private Map<String, String> extensions;

		public CEFEvent() {
			extensions = new HashMap<>();
		}

		public byte getCefVersion() {
			return cefVersion;
		}

		public void setCefVersion(byte cefVersion) {
			this.cefVersion = cefVersion;
		}

		public String getVendor() {
			return vendor;
		}

		public void setVendor(String vendor) {
			this.vendor = vendor;
		}

		public String getProduct() {
			return product;
		}

		public void setProduct(String product) {
			this.product = product;
		}

		public String getVersion() {
			return version;
		}

		public void setVersion(String version) {
			this.version = version;
		}

		public String getSignature() {
			return signature;
		}

		public void setSignature(String signature) {
			this.signature = signature;
		}

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public byte getSeverity() {
			return severity;
		}

		public void setSeverity(byte severity) {
			this.severity = severity;
		}

		public Map<String, String> getExtensions() {
			return extensions;
		}

		@Override
		public String toString() {
			return "CEFEvent [cefVersion=" + ((char) cefVersion) + ", vendor=" + vendor + ", product=" + product
					+ ", version=" + version + ", signature=" + signature + ", name=" + name + ", severity=" + severity
					+ ", extensions=" + extensions + "]";
		}

	}

}
