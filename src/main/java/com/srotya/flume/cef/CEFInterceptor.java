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

import org.apache.flume.Context;
import org.apache.flume.Event;
import org.apache.flume.interceptor.Interceptor;

/**
 * An Apache Flume interceptor for parsing Common Event Format (CEF)
 * events
 * 
 * @author ambudsharma
 */
public class CEFInterceptor implements Interceptor {

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
				Utils.parseToCEFOptimized(event.getHeaders(), cefBody);
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
	 * Builder for {@link CEFInterceptor}
	 * 
	 * @author ambudsharma
	 */
	public static class Builder implements Interceptor.Builder {

		@Override
		public void configure(Context arg0) {
		}

		@Override
		public Interceptor build() {
			return new CEFInterceptor();
		}
		
	}

}