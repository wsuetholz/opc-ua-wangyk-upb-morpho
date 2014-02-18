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

package org.opcfoundation.ua.encoding.utils;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opcfoundation.ua.builtintypes.BuiltinsMap;
import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.encoding.IEncodeable;

/**
 * Contains information about IEncodeable class
 * 
 * @see EncodeableDescTable table of stub infos
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public final class EncodeableDesc {
	
	public final Class<? extends IEncodeable>	clazz;
	public final FieldInfo[]		fields;
	public final NodeId				binaryId;
	public final NodeId				xmlId;
	public final NodeId				id;
	public final String				url;
	public final int				length;
	public final Map<String, FieldInfo> fieldNameMap = new HashMap<String, FieldInfo>();	
	
	public EncodeableDesc(Class<? extends IEncodeable> clazz,		
			FieldInfo[] fields, NodeId id, String url, NodeId binaryId, NodeId xmlId) {
		if (clazz == null || fields==null /*|| url==null  || id==null || xmlId==null || binaryId==null*/ )
			throw new IllegalArgumentException("null");
		this.binaryId = binaryId;
		this.clazz = clazz;
		this.fields = fields;
		this.id = id;
		this.url = url;
		this.xmlId = xmlId;
		this.length = fields.length;
		for (FieldInfo fi : fields)
			fieldNameMap.put(fi.field.getName(), fi);
	}
	
	private static void getAllFields(Class<?> clazz, List<Field> list)
	{
		for (Field f : clazz.getDeclaredFields())
			list.add(f);
		if (clazz.getSuperclass()!=null)
			getAllFields(clazz.getSuperclass(), list);		
	}

	static FieldInfo readFieldInfoFromClass(Field f)
	{
		f.setAccessible(true);
		Class<?> clazz			= f.getType();
		Integer builtinType		= BuiltinsMap.ID_MAP.get(clazz);
		int bt					= builtinType == null ? -1 : builtinType;
		boolean isArray			= clazz.isArray() && !clazz.equals(byte[].class);
		return new FieldInfo(bt, f, isArray, clazz);
	}	
	
	public static EncodeableDesc readFromClass(Class<? extends IEncodeable> clazz)
	{
		ArrayList<Field> allFields = new ArrayList<Field>();
		getAllFields(clazz, allFields);
		ArrayList<FieldInfo> fields	= new ArrayList<FieldInfo>(Math.max(0, allFields.size()-4));
		NodeId binaryId=null, id=null, xmlId=null;
		String url=null;
		
		try {
			for (Field f : allFields)
			{
				// static
				f.setAccessible(true);
				if ((f.getModifiers() & 8) == 8) {
					if (f.getName().equals("BINARY"))
						binaryId = (NodeId) f.get(null);
					if (f.getName().equals("XML"))
						xmlId = (NodeId) f.get(null);
					if (f.getName().equals("ID"))
						id = (NodeId) f.get(null);
					if (f.getName().equals("URL"))
						url = (String) f.get(null);
				} else {
					FieldInfo fi = readFieldInfoFromClass(f);
					fields.add( fi );
				}
			}
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
		
		//if (binaryId==null||xmlId==null||id==null||url==null)
		//	throw new RuntimeException(clazz+" is not a well defined structure class");
		
		return new EncodeableDesc(
				clazz, 
				fields.toArray(new FieldInfo[fields.size()]),
				id, 
				url, 
				binaryId, 
				xmlId);		
	}	
	
	public static class FieldInfo {
		public final Field				field;
		public final Class<?>			type;
		public final int				builtinType;
		public final boolean			isArray;
		public FieldInfo(int builtinType, Field field, boolean isArray, Class<?> type) {
			this.builtinType = builtinType;
			this.field = field;
			this.isArray = isArray;
			this.type = type;
		}
	}
	
}
