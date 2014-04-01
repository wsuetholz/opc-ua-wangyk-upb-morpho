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

package builtintypes;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.UUID;

import common.NamespaceTable;
import core.IdType;
import core.Identifiers;


/**
 * A NodeId that allows the NamespaceUri to be specified explicitly instead of NamespaceIndex.
 * ExpandedNodeId may still use NamespaceIndex.
 * <p>
 * Instances of ExpandedNodeId are equals comparable only within server context.
 * <p> 
 * ExpandedNodeIds are equals comparable with NodeIds if they are constructed with NamespaceIndex
 * and no ServerIndex.
 * 
 * @see NodeId Id with NamespaceIndex and not ServerIndex
 * @see NamespaceTable For converting ExpandedNodeIds to NodeIds
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public final class ExpandedNodeId {

	/** Considered null node id */
	/** Considered null node id */	
	public static final ExpandedNodeId NULL_NUMERIC = new ExpandedNodeId(NodeId.NULL_NUMERIC);
	public static final ExpandedNodeId NULL = NULL_NUMERIC;
	
	/** Identifier of "NodeId" in UA AddressSpace */
	public static final NodeId ID = Identifiers.ExpandedNodeId;	
	
	IdType type;
	int namespaceIndex;
	UnsignedInteger serverIndex;
	String namespaceUri;
	Object value;
	int hashCode;
	
	/**
	 * Construct ExpandedNodeId using NamespaceIndex.
	 * 
	 * @param serverIndex Server Index (optional)
	 * @param namespaceIndex namespace index
	 * @param value value (must be UnsignedInteger, String, UUID, byte[] or null)
	 */
	public ExpandedNodeId(UnsignedInteger serverIndex, int namespaceIndex, Object value)
	{
		if (namespaceIndex<0 || namespaceIndex>65535) 
			throw new IllegalArgumentException("namespaceIndex out of bounds");
		this.serverIndex = serverIndex;
		if (value instanceof Integer) value = UnsignedInteger.getFromBits((Integer)value);
		this.value = value;
		this.namespaceIndex = namespaceIndex;	
		if (value!=null)
			hashCode += value instanceof byte[] ? 3*Arrays.hashCode((byte[])value) : 3*value.hashCode();
		this.hashCode += 13*namespaceIndex;
		if (serverIndex!=null) hashCode += serverIndex.hashCode()*17;
		
		else if (value instanceof UnsignedInteger) type = IdType.Numeric;
		else throw new IllegalArgumentException("value cannot be "+value.getClass().getName());		
	}
	
	/**
	 * Construct ExpandedNodeId using NamespaceUri.
	 * 
	 * @param serverIndex Server Index (optional)
	 * @param namespaceUri
	 * @param value value (must be UnsignedInteger, String, UUID or byte[])
	 */
	public ExpandedNodeId(UnsignedInteger serverIndex, String namespaceUri, Object value)
	{
		if (namespaceIndex<0 || namespaceIndex>65535) 
			throw new IllegalArgumentException("namespaceIndex out of bounds");
		this.serverIndex = serverIndex;
		this.value = value;
		this.namespaceUri = namespaceUri;
		if (value!=null)
			hashCode += value instanceof byte[] ? 3*Arrays.hashCode((byte[])value) : 3*value.hashCode();

		if (namespaceUri!=null) hashCode += 13*namespaceUri.hashCode();
		if (serverIndex!=null) hashCode += 17*serverIndex.hashCode();
		
		else if (value instanceof UnsignedInteger) type = IdType.Numeric;
		else throw new IllegalArgumentException("value cannot be "+value.getClass().getName());
	}		
	
	/**
	 * Convenience constructor that creates ExpandedNodeId from 
	 * NamespaceIndex and Identifier of an nodeId.
	 * 
	 * @param serverIndex Server Index (optional)
	 * @param nodeId nodeId
	 */
	public ExpandedNodeId(UnsignedInteger serverIndex, NodeId nodeId) {
		this(serverIndex, nodeId.getNamespaceIndex(), nodeId.getValue());
    }

	/**
	 * Convenience constructor that creates ExpandedNodeId from 
	 * NamespaceIndex and Identifier of an nodeId. Server Index is null.
	 * 
	 * @param nodeId nodeId
	 */
	public ExpandedNodeId(NodeId nodeId) {
		this(null, nodeId.getNamespaceIndex(), nodeId.getValue());
    }
	
	/**
	 * Tests whether this node is null node
	 * 
	 * @return true if this node is a null node
	 */
	public boolean isNullNodeId() {		
		return equals(ExpandedNodeId.NULL);
	}
	/*
	 * returns true if the nodeId is absolute, i.e. it refers to an external server (with namespaceUri or serverIndex). 
	 *
	 */
	public boolean isAbsolute(){
		return ((namespaceUri != null && !namespaceUri.isEmpty()) || (serverIndex != null && serverIndex.intValue() > 0));
	}

	public IdType getIdType()
	{
		return type;
	}
	
	/**
	 * Get NamespaceIndex if this ExpandedNodeId was constructed with one. 
	 *  
	 * @return NamespaceIndex or null
	 */
	public int getNamespaceIndex()
	{
		return namespaceIndex;
	}
	
	public Object getValue()
	{
		return value;
	}

	public UnsignedInteger getServerIndex()
	{
		return serverIndex;
	}
	
	/**
	 * Get NamespaceUri if this ExpandedNodeId was constructed with one. 
	 *  
	 * @return NamespaceUri or null
	 */
	public String getNamespaceUri()
	{
		return namespaceUri;
	}
	
	@Override
	public int hashCode() {
		return hashCode;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (obj == null) return this.equals(ExpandedNodeId.NULL);
		if (obj instanceof NodeId) {
			if (namespaceUri!=null || serverIndex!=null) return false;
			NodeId other = (NodeId) obj;
			if (this.value==other.value) return true;		
			return other.value.equals(value);
		} else
		if (obj instanceof ExpandedNodeId) {
			ExpandedNodeId other = (ExpandedNodeId) obj;
			if (namespaceUri!=null) {
				if (other.namespaceUri==null || !other.namespaceUri.equals(namespaceUri)) return false;
			} else {
				if (other.namespaceUri!=null) return false;
				if (other.namespaceIndex!=namespaceIndex) return false;
			}
			if (serverIndex!=null) {
				if (other.serverIndex==null || !other.serverIndex.equals(serverIndex)) return false;				
			} else {
				if (other.serverIndex!=null) return false;
			}
			if (other.type!=type) return false;
			if (this.value==other.value) return true;
			if (other.value != null) {
				return other.value.equals(value);
			} else {
				return value == null;
			}
		} else
		return false;
	}
	
	@Override
	public String toString() {
		try {
			String srvPart = serverIndex!=null && serverIndex.getValue()!=0 ? "srv="+serverIndex+";" : "";
			String nsPart = namespaceUri!=null ? "nsu="+URLEncoder.encode(namespaceUri, "ISO8859-1")+";" : namespaceIndex>0 ? "ns="+namespaceIndex+";" : "";
			if (type == IdType.Numeric) return srvPart+nsPart+"i="+value;
		} catch (UnsupportedEncodingException e) {
		}
		return "error";
	}

	/**
	 * Check if nodeId is null or a NullNodeId.
	 * @param nodeId
	 * @return true if (nodeId == null) || nodeId.isNullNodeId()
	 */
	public static boolean isNull(ExpandedNodeId nodeId) {
		return (nodeId == null) || nodeId.isNullNodeId();
	}

	/**
	 * Check if the nodeId refers to a local node, i.e. a node that is in the server's own namespace. 
	 * @return true, if serverIndex == 0 (or null)
	 */
	public boolean isLocal() {
		return (serverIndex == null) || (serverIndex.getValue() == 0);
	}

	/**
	 * Check if this ExpandedNodeId equals to the given NodeId. Normal #equals
	 * check will always fail, because the objects are of different type.
	 * 
	 * @param nodeId
	 * @return
	 */
	public boolean equalsNodeId(NodeId nodeId) {
		// TODO Auto-generated method stub
		return false;
	}
	


}
