/* ========================================================================
 * Copyright (c) 2005-2010 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Reciprocal Community License ("RCL") Version 1.00
 * 
 * Unless explicitly acquired and licensed from Licensor under another 
 * license, the contents of this file are subject to the Reciprocal 
 * Community License ("RCL") Version 1.00, or subsequent versions as 
 * allowed by the RCL, and You may not copy or use this file in either 
 * source code or executable form, except in compliance with the terms and 
 * conditions of the RCL.
 * 
 * All software distributed under the RCL is provided strictly on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, 
 * AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT 
 * LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RCL for specific 
 * language governing rights and limitations under the RCL.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/RCL/1.00/
 * ======================================================================*/

package org.opcfoundation.ua.builtintypes;

import java.io.Serializable;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import org.opcfoundation.ua.core.Identifiers;

/**
 * OPC UA DateTime.
 * The OPC UA dateTime is defined as follows (OPCUA Part 3)
 * 
 * 7.29 UtcTime
 * This primitive DataType is used to define Coordinated Universal Time (UTC) values. 
 * All time values conveyed between servers and clients in OPC UA are UTC values. 
 * Clients must provide any conversions between UTC and local time.
 * This DataType is represented as a 64-bit signed integer which represents the number 
 * of 100 nanosecond intervals since January 1, 1601. 
 * [UA Part 6] defines details about this DataType.
 * 
 * @author Jouni.Aro@prosys.fi
 *
 */
public class DateTime implements Serializable, Comparable<DateTime> {

	private static final long serialVersionUID = 2701845992071716850L;

	public static final NodeId ID = Identifiers.DateTime;
	
	// The correct one
//    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");
	
	// Fallback logic in java uses GMT anyway.
	private static final TimeZone UTC = TimeZone.getTimeZone("GMT");
    
	public static final long OffsetToGregorianCalendarZero = 116444736000000000L; // Diff between 1970/1/1 and 1601/1/1

	public static final DateTime MIN_VALUE = new DateTime(0);
	public static final DateTime MAX_VALUE = new DateTime(9999, Calendar.JANUARY, 1, 23, 59, 59, 0);
	private final long value;
	
	/**
	 * Constructs a new DateTime value, initializing it with the current UTC time.
	 */
	public DateTime() {
		this(GregorianCalendar.getInstance());
	}

	/**
	 * Constructs a new DateTime value, initializing it with an OPC UA time value.
	 */
	public DateTime(long value) {
		this.value = value;
	}

	/**
	 * Constructs a new DateTime value, is initializing it with a Calendar value.
	 */
	public DateTime(Calendar value) {
		this.value = value.getTimeInMillis()*10000 + OffsetToGregorianCalendarZero;
	}

	/**
	 * Constructs a new DateTime value, initializing it with the given time value (in UTC timezone).
	 */
	public DateTime(int year, int month, int day, int hour, int minute, int second, int nanosecond, TimeZone timeZone) {
		Calendar c = new GregorianCalendar(year, month, day, hour, minute, second);
		c.setTimeZone(timeZone);
		this.value = (nanosecond / 100) + c.getTimeInMillis()*10000 + OffsetToGregorianCalendarZero;
	}

	public DateTime(int year, int month, int day, int hour, int minute, int second, int nanosecond) {
		this(year, month, day, hour, minute, second, nanosecond, UTC);
	}

	/**
	 * Get 1/100 microseconds (1 unit = 10 nanoseconds) between
     * the time and midnight, January 1, 1601 UTC. 
	 * @return time value 
	 */
	public long getValue() {
		return value;
	}
	
	/**
	 * Get milliseconds (1 unit = 10 nanoseconds) between
     * the time and midnight, January 1, 1601 UTC.
     * 
	 * @return time in milliseconds since January 1, 1601 UTC midnight
	 */
	public long getMilliSeconds() {
		return value / 10000;
	}

	/**
	 * Get milliseconds (1 unit = 10 nanoseconds) between
     * the time and midnight, January 1, 1970 UTC. 
     * This equals to the value returned by the respective 
     * Calendar instance, returned by getCalendar. 
	 * 
	 * @return milliseconds since January 1, 1970 UTC midnight
	 */
	public long getTimeInMillis() {
		return (value - OffsetToGregorianCalendarZero) / 10000;
	}
	
	public String toString() {
		final GregorianCalendar c = getUtcCalendar();
		long nanos = value % 10000000; 
		return String.format("%TD %TT.%07d %TZ", c, c, nanos, c); // yyyy/mm/dd HH:MM:SS.LLL
	}
	
	/**
	 * @return the dateTime converted to a new GregorianCalendar in UTC TimeZone.
	 */
    public GregorianCalendar getUtcCalendar() {
    	return getCalendar(UTC);
	}

	/**
	 * @return the dateTime converted to a new GregorianCalendar in local TimeZone.
	 */
    public GregorianCalendar getLocalCalendar() {
    	return getCalendar(TimeZone.getDefault());
	}

    /**
     * Return the time as a calendar value.
     * @param timezone The desired TimeZone for the calendar
     * @return a new GregorianCalendar instance, initialized to the value of the DateTime.
     */
    public GregorianCalendar getCalendar(TimeZone timezone) {
    	GregorianCalendar c = new GregorianCalendar(timezone);
    	c.setTimeInMillis(getTimeInMillis());
    	return c;
	}

	@Override
	public int hashCode() {
		return (int) (value ^ (value >> 32));
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		final DateTime other = (DateTime) obj;
		if (value != other.value)
			return false;
		return true;
	}

	@Override
	public int compareTo(DateTime o) {
		if (value < o.value)
			return -1;
		if (value > o.value)
			return 1;
		return 0;
	}

	/**
	 * @return an instance of DateTime with the current time.
	 */
	public static DateTime currentTime() {
		return new DateTime();
	}

}
