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

package encoding.binary;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Set;

import builtintypes.Enumeration;
import builtintypes.NodeId;
import builtintypes.ServiceResponse;
import encoding.DecodingException;
import encoding.EncodeType;
import encoding.EncodingException;
import encoding.IDecoder;
import encoding.IEncodeable;
import encoding.IEncoder;
import encoding.utils.EncodeableDesc;
import encoding.utils.EncodeableDescTable;

/**
 * Serializes {@link IEncodeable}s using reflection.
 * This class can encode anything that implements IEncodeable.
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class EncodeableReflectionSerializer implements IEncodeableSerializer {

	private static EncodeableReflectionSerializer DEFAULT;
	
	/**
	 * Get default implementation
	 * @return default implementation
	 */
	public synchronized static EncodeableReflectionSerializer getDefault()
	{
		if (DEFAULT==null) {
			DEFAULT = new EncodeableReflectionSerializer(EncodeableDescTable.getDefault());
		}
		return DEFAULT;
	}
	
	EncodeableDescTable encodeableTable;
	Set<Class<? extends IEncodeable>> encodeSet;
	Set<NodeId> decodeSet;
	
	public EncodeableReflectionSerializer(EncodeableDescTable table)
	{
		this.encodeableTable = table;
		encodeSet = table.getClassMap().keySet();
		decodeSet = table.getBinIdMap().keySet();
	}
	
	@Override
	public void calcEncodeable(Class<? extends IEncodeable> clazz, IEncodeable encodeable, IEncoder calculator) 
	throws EncodingException 
	{		
		EncodeableDesc si = encodeableTable.get(clazz);
		if (si==null) throw new EncodingException("Cannot encode "+clazz);
		
		try {
			for (EncodeableDesc.FieldInfo fi : si.fields)
			{
				Field f					= fi.field;
				Object value			= encodeable==null ? null : f.get(encodeable);
				calculator.putObject(fi.field.getName(), fi.type, value);
			}
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public IEncodeable getEncodeable(Class<? extends IEncodeable> clazz, IDecoder decoder) throws DecodingException
	{
		EncodeableDesc info = encodeableTable.get(clazz);
		if (info==null) throw new DecodingException("Cannot decode "+clazz);
		try {
			IEncodeable result = info.clazz.newInstance();
			for (EncodeableDesc.FieldInfo fi : info.fields)
			{
				// Decode builtin type
				if (fi.builtinType>=0) {
					Object value = fi.isArray ? decoder.getArrayObject(fi.field.getName(), fi.builtinType) : decoder.getScalarObject(fi.field.getName(), fi.builtinType);
					fi.field.set(result, value);
					continue;
				} 
				
				// Decode encodeable 
				EncodeableDesc vi = encodeableTable.get((Class<? extends IEncodeable>) fi.type);
				if (vi!=null) {
					Object value = fi.isArray ? decoder.getEncodeableArray(fi.field.getName(), vi.clazz) : getEncodeable(vi.clazz, decoder);
					fi.field.set(result, value);
					continue;
				}
				
				// Decode enumeration
				if (!fi.isArray && Enumeration.class.isAssignableFrom( fi.type ))
				{
					Object value = decoder.getEnumeration(fi.field.getName(), (Class<Enumeration>) fi.type);
					fi.field.set(result, value);
					continue;					
				}
				
				// Decode enumeration array
				if (fi.isArray && Enumeration.class.isAssignableFrom( fi.type.getComponentType() ))
				{
					Object value = decoder.getEnumerationArray(fi.field.getName(), (Class<Enumeration>) fi.type.getComponentType());
					fi.field.set(result, value);
					continue;					
				}
 
				throw new DecodingException("Cannot decode "+fi.type);
			}
			// Fixes diagnostic infos to point string table of the message
			if (result instanceof ServiceResponse) {
				DecoderUtils.fixResponseHeader(  ((ServiceResponse)result).getResponseHeader() );
			}
			return result;			
		} catch (InstantiationException e) {
			throw new RuntimeException(e);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}
	

	@Override
	public void putEncodeable(Class<? extends IEncodeable> clazz,
			IEncodeable encodeable, IEncoder encoder) throws EncodingException
	{
		EncodeableDesc si = encodeableTable.get(clazz);	
		if (si==null) throw new EncodingException("Cannot encode "+clazz);
		
		try {
			for (EncodeableDesc.FieldInfo fi : si.fields)
			{
				Field f					= fi.field;
				Object value			= encodeable==null ? null : f.get(encodeable);
				encoder.putObject(fi.field.getName(), fi.type, value);
			}
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}	

	@Override
	public void getSupportedNodeIds(Collection<NodeId> result) {
		result.addAll(decodeSet);
	}
	
	@Override
	public void getSupportedClasses(Collection<Class<? extends IEncodeable>> result)
	{
		result.addAll(encodeSet);
	}

	@Override
	public Class<? extends IEncodeable> getClass(NodeId id) {
		EncodeableDesc info = encodeableTable.get(id);
		if (info == null) return null;
		return info.clazz;
	}
	
	@Override
	public NodeId getNodeId(Class<? extends IEncodeable> clazz, EncodeType type) {
		EncodeableDesc info = encodeableTable.get(clazz);
		if (info == null) return null;
		if (type==EncodeType.Binary)
			return info.binaryId;
		if (type==EncodeType.Xml)
			return info.xmlId;
		return null;
	}

}
