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

package encoding.utils;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import builtintypes.NodeId;
import encoding.IEncodeable;
import transport.tcp.impl.Acknowledge;
import transport.tcp.impl.ErrorMessage;
import transport.tcp.impl.Hello;

/**
 * Table containing descriptions of stub classes. 
 * 
 * @see EncodeableDesc
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class EncodeableDescTable {

	/**
	 * Get default structure table that is built with default discovered encoders
	 *  
	 * @return encodeable description table
	 */
	public synchronized static EncodeableDescTable getDefault()
	{
		if (DEFAULT==null) {
			Collection<Class<IEncodeable>> classes = EncodeableDiscovery.getDefault().values();
			DEFAULT = readFromClasses( classes );
			DEFAULT.addStructureInfo( EncodeableDesc.readFromClass(Acknowledge.class) );
			DEFAULT.addStructureInfo( EncodeableDesc.readFromClass(Hello.class) );
			DEFAULT.addStructureInfo( EncodeableDesc.readFromClass(ErrorMessage.class) );
		}
		return DEFAULT;
	}	
	
	/**
	 * Create Structure table from a collection of classes.
	 * 
	 * @param map
	 * @return encodeable description table
	 */
	public static EncodeableDescTable readFromClasses(Collection<Class<IEncodeable>> map)
	{
		EncodeableDescTable result = new EncodeableDescTable();
		for (Class<IEncodeable> e : map)
		{
			EncodeableDesc si = EncodeableDesc.readFromClass(e);
			result.addStructureInfo(si);
		}
		return result;
	}	
	
	private Map<Class<? extends IEncodeable>, EncodeableDesc> classMap = new HashMap<Class<? extends IEncodeable>, EncodeableDesc>();
	private Map<NodeId, EncodeableDesc> idMap = new HashMap<NodeId, EncodeableDesc>();
	private Map<NodeId, EncodeableDesc> binIdMap = new HashMap<NodeId, EncodeableDesc>();
	private Map<NodeId, EncodeableDesc> xmlIdMap = new HashMap<NodeId, EncodeableDesc>();
	private Map<Class<? extends IEncodeable>, EncodeableDesc> _classMap = Collections.unmodifiableMap(classMap);
	private Map<NodeId, EncodeableDesc> _idMap = Collections.unmodifiableMap(idMap);
	private Map<NodeId, EncodeableDesc> _binIdMap = Collections.unmodifiableMap(binIdMap);
	private Map<NodeId, EncodeableDesc> _xmlIdMap = Collections.unmodifiableMap(xmlIdMap);
	
	private static EncodeableDescTable DEFAULT;
	
	public EncodeableDesc get(Class<?> clazz)
	{
		return classMap.get(clazz);
	}
	
	public EncodeableDesc get(NodeId id)
	{
		return idMap.get(id);
	}

	
	public void addStructureInfo(EncodeableDesc s)
	{
		classMap.put(s.clazz, s);
		//classMap.put(getArrayClass(s.clazz), s);
		idMap.put(s.binaryId, s);
		idMap.put(s.xmlId, s);
		idMap.put(s.id, s);
		binIdMap.put(s.binaryId, s);
		xmlIdMap.put(s.binaryId, s);
	}
	
	public Map<NodeId, EncodeableDesc> getIdMap()
	{
		return _idMap;		
	}
	
	public Map<NodeId, EncodeableDesc> getBinIdMap()
	{
		return _binIdMap;
	}
	
	public Map<NodeId, EncodeableDesc> getXmlIdMap()
	{
		return _xmlIdMap;
	}
	
	public Map<Class<? extends IEncodeable>, EncodeableDesc> getClassMap()
	{
		return _classMap;
	}
	
}
