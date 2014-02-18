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

import java.util.Arrays;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.opcfoundation.ua.encoding.DecodingException;
import org.opcfoundation.ua.utils.MultiDimensionArrayUtils;

/**
 * Variant wraps an arbitrary builtin variable, an array of builtin variables or
 * a multi-dimension array of builtin variable. Variant is equals-comparable.
 * <p>
 * An example: Variant v = new Variant( new UnsignedInteger[4][5][6] );
 * <p> 
 * The value may be builtin primitive or a {@link Structure}. 
 *  e.g. new Variant( new NotificationData() );
 * 
 * Encoders write a structure as an {@link ExtensionObject}. 
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class Variant {
	private static Logger logger = Logger.getLogger(Variant.class);

	public static final Variant NULL = new Variant(null);
	Object value;
	Class<?> compositeClass;

	/**
	 * Create variant.
	 * 
	 * @param value
	 *            scalar, array or multi-dimension array
	 */
	public Variant(Object value) {
		if (value instanceof ExtensionObject)
			try {
				value = ((ExtensionObject)value).decode();
			} catch (DecodingException e) {
				logger.error("Unknown ExtensionObject", e);
			}
		if (value instanceof Enumeration)
			value = ((Enumeration) value).getValue();
		this.value = value;
		if (value != null) {
			compositeClass = value.getClass();
			
			if(compositeClass == Variant.class) {
				throw new IllegalArgumentException("Variant cannot be "
						+ compositeClass.getCanonicalName());
			}
			
			while (compositeClass.isArray()
					&& !compositeClass.equals(byte[].class))
				compositeClass = compositeClass.getComponentType();
			
			assertValidClass(compositeClass);
		}
	}

	void assertValidClass(Class<?> clazz) {
		if (clazz.equals(byte[].class))
			return;
		if (clazz.equals(Boolean.class))
			return;
		if (clazz.equals(Byte.class))
			return;
		if (clazz.equals(UnsignedByte.class) && !clazz.isArray())
			return;
		if (clazz.equals(Short.class))
			return;
		if (clazz.equals(UnsignedShort.class))
			return;
		if (clazz.equals(Integer.class))
			return;
		if (clazz.equals(UnsignedInteger.class))
			return;
		if (clazz.equals(Long.class))
			return;
		if (clazz.equals(UnsignedLong.class))
			return;
		if (clazz.equals(Float.class))
			return;
		if (clazz.equals(Double.class))
			return;
		if (clazz.equals(String.class))
			return;
		if (clazz.equals(DateTime.class))
			return;
		if (clazz.equals(UUID.class))
			return;
		if (clazz.equals(XmlElement.class))
			return;
		if (clazz.equals(NodeId.class))
			return;
		if (clazz.equals(ExpandedNodeId.class))
			return;
		if (clazz.equals(StatusCode.class))
			return;
		if (clazz.equals(QualifiedName.class))
			return;
		if (clazz.equals(LocalizedText.class))
			return;
		if (clazz.equals(Structure.class))
			return;
		if (clazz.equals(ExtensionObject.class))
			return;
		if (clazz.equals(DataValue.class))
			return;
		if (clazz.equals(DiagnosticInfo.class))
			return;
		if (clazz.equals(Variant.class))
			return;
		if (Structure.class.isAssignableFrom(clazz))
			return;
		if (Enumeration.class.isAssignableFrom(clazz))
			return;
		throw new IllegalArgumentException("Variant cannot be "
				+ clazz.getCanonicalName());
	}

	public boolean isEmpty() {
		return value == null;
	}

	public boolean isArray() {
		if (value == null)
			return false;
		Class<?> c = value.getClass();
		return c.isArray() && !c.equals(byte[].class);
	}

	public Object getValue() {
//		if (value instanceof ExtensionObject) 
//			try {
//				return ((ExtensionObject) value).decode();
//			} catch (DecodingException e) {
//				//e.printStackTrace();
//			}
		return value;
	}

	@Override
	public String toString() {
		if (value == null)
			return "(null)";
		if (isArray()) {
			int[] d = getArrayDimensions();
			StringBuilder sb = new StringBuilder();
			sb.append(d[0]);
			for (int i = 1; i < getDimension(); i++)
				sb.append(",").append(d[i]);
			return String.format("(%s[%s]) %s", compositeClass.toString(), sb
					.toString(), MultiDimensionArrayUtils.toString(value));
		}
		return String.format("(%s) %s", compositeClass.toString(), value
				.toString());
	}

	/**
	 * The class type of the variant value. If the value is an array, the type
	 * may be an ExtensionObject, in which case the array elements must be
	 * decoded to find out the actual type of each.
	 * 
	 * @return the class of Value
	 */
	public Class<?> getCompositeClass() {
		return compositeClass;
	}

	public int[] getArrayDimensions() {
		int dim = getDimension();
		int result[] = new int[dim];
		if (dim == 0)
			return result;

		Object o = value;
		for (int i = 0; i < dim; i++) {
			Object[] array = (Object[]) o;
			result[i] = array.length;
			if (array.length == 0)
				break;
			o = array[0];
		}

		return result;
	}

	public int getDimension() {
		int dim = MultiDimensionArrayUtils.getDimension(value);
		if (compositeClass.isArray())
			dim--;
		return dim;
	}

	@Override
	public int hashCode() {
		if (value == null)
			return 0;
		if (!isArray())
			return value.hashCode();
		if (value instanceof byte[])
			return Arrays.hashCode((byte[]) value);
		return Arrays.deepHashCode((Object[]) value);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null)
			return false;
		if (!(obj instanceof Variant))
			return false;
		Variant o = (Variant) obj;
		if (value == null && o.value == null)
			return true;
		if (value == null && o.value != null)
			return false;
		if (value != null && o.value == null)
			return false;

		Class<?> c = value.getClass();
		if (!c.equals(o.value.getClass()))
			return false;

		if (c == byte[].class)
			return Arrays.equals((byte[]) o.value, (byte[]) value);

		if (!isArray())
			return value.equals(o.value);
		return Arrays.deepEquals((Object[]) value, (Object[]) o.value);
	}

	/**
	 * Convert the variant value to any class. If it cannot be converted returns null. 
	 * @param clazz The class type to convert to.
	 * @param defaultValue A default value to return, if the conversion cannot be done
	 * @return Value as the requested class or defaultValue, if it cannot be converted.
	 */
	public <T> T asClass(Class<T> clazz, T defaultValue) {
		if (value == null)
			return defaultValue;
		try {
			return clazz.cast(value);
		} catch (ClassCastException e) {
			return defaultValue;
		}
	}

	/**
	 * Returns the value of the specified Variant as a <code>boolean</code>
	 * 
	 * @return the Variant value as boolean, if it can be cast to such
	 * @throws ClassCastException if the value cannot be cast to boolean
	 */
	public boolean booleanValue() {
		return asClass(Boolean.class, false);
	}

	/**
	 * Returns the value of the specified Variant as a <code>Number</code>
	 * 
	 * @return the Variant value as Number, if it can be cast to such
	 * @throws ClassCastException if the value cannot be cast to Number
	 */
	public Number toNumber() {
		if (value instanceof Number)
			return (Number) value;
		throw new ClassCastException("Variant is not a Number; CompositeClass="
				+ compositeClass);
	}
	
    /**
     * Returns the value of the specified Variant as an <code>int</code>.
     * This may involve rounding or truncation.
     *
     * @return  the numeric value represented by this object after conversion
     *          to type <code>int</code>.
	 * @throws ClassCastException if the value cannot be cast to Number
     */
    public int intValue() {
		return toNumber().intValue();
	}

    /**
     * Returns the value of the specified Variant as a <code>long</code>.
     * This may involve rounding or truncation.
     *
     * @return  the numeric value represented by this object after conversion
     *          to type <code>long</code>.
	 * @throws ClassCastException if the value cannot be cast to Number
     */
    public long longValue() {
		return toNumber().longValue();
	}

    /**
     * Returns the value of the specified Variant as a <code>float</code>.
     * This may involve rounding.
     *
     * @return  the numeric value represented by this object after conversion
     *          to type <code>float</code>.
	 * @throws ClassCastException if the value cannot be cast to Number
     */
    public float floatValue() {
		return toNumber().floatValue();
	}

    /**
     * Returns the value of the specified Variant as a <code>double</code>.
     * This may involve rounding.
     *
     * @return  the numeric value represented by this object after conversion
     *          to type <code>double</code>.
 	 * @throws ClassCastException if the value cannot be cast to Number
    */
    public double doubleValue() {
		return toNumber().floatValue();
	}

    /**
     * Returns the value of the specified Variant as a <code>byte</code>.
     * This may involve rounding or truncation.
     *
     * @return  the numeric value represented by this object after conversion
     *          to type <code>byte</code>.
 	 * @throws ClassCastException if the value cannot be cast to Number
    */
    public byte byteValue() {
	return toNumber().byteValue();
    }

    /**
     * Returns the value of the specified Variant as a <code>short</code>.
     * This may involve rounding or truncation.
     *
     * @return  the numeric value represented by this object after conversion
     *          to type <code>short</code>.
 	 * @throws ClassCastException if the value cannot be cast to Number
     */
    public short shortValue() {
	return toNumber().shortValue();
    }
	
}
