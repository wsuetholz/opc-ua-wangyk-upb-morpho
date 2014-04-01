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

package encoding;

import java.util.UUID;

import builtintypes.DataValue;
import builtintypes.DateTime;
import builtintypes.DiagnosticInfo;
import builtintypes.Enumeration;
import builtintypes.ExpandedNodeId;
import builtintypes.LocalizedText;
import builtintypes.NodeId;
import builtintypes.QualifiedName;
import builtintypes.StatusCode;
import builtintypes.Structure;
import builtintypes.UnsignedByte;
import builtintypes.UnsignedInteger;
import builtintypes.UnsignedShort;
import builtintypes.Variant;


/**
 *
 * 
 * @see IEncoder
 * @see BinaryDecoder
 * @see XmlDecoder
 */
public interface IDecoder {
	
    void pushNamespace(String namespaceUri);
    void popNamespace();	
	
	public Boolean getBoolean(String fieldName)
    throws DecodingException;	
	
	public Boolean[] getBooleanArray(String fieldName)
    throws DecodingException;	
	
	public Byte getSByte(String fieldName)
    throws DecodingException;	
	
	public Byte[] getSByteArray(String fieldName)
    throws DecodingException;	
	
	public UnsignedByte getByte(String fieldName)
    throws DecodingException;	
	
	public UnsignedByte[] getByteArray(String fieldName)
    throws DecodingException;	
	
	public Short getInt16(String fieldName)
    throws DecodingException;	
	
	public Short[] getInt16Array(String fieldName)
    throws DecodingException;	
	
	public UnsignedShort getUInt16(String fieldName)
    throws DecodingException;	
	
	public UnsignedShort[] getUInt16Array(String fieldName)
    throws DecodingException;	
	
	public Integer getInt32(String fieldName)
    throws DecodingException;	
	
	public Integer[] getInt32Array(String fieldName)
    throws DecodingException;	
	
	public int[] getInt32Array_(String fieldName)
    throws DecodingException;	
	
	public UnsignedInteger getUInt32(String fieldName)
    throws DecodingException;	
	
	public UnsignedInteger[] getUInt32Array(String fieldName)
    throws DecodingException;	
	
	public Long getInt64(String fieldName)
    throws DecodingException;	
	
	public Long[] getInt64Array(String fieldName)
    throws DecodingException;	
	
	public Float getFloat(String fieldName)
    throws DecodingException;	
	
	public Float[] getFloatArray(String fieldName)
    throws DecodingException;	
	
	public Double getDouble(String fieldName)
    throws DecodingException;	
	
	public Double[] getDoubleArray(String fieldName)
    throws DecodingException;	
	
	public String getString(String fieldName)
    throws DecodingException;	
	
	public String[] getStringArray(String fieldName)
    throws DecodingException;	
	
	public DateTime getDateTime(String fieldName)
    throws DecodingException;	
	
	public DateTime[] getDateTimeArray(String fieldName)
    throws DecodingException;	
	
	public UUID getGuid(String fieldName)
    throws DecodingException;	
	
	public UUID[] getGuidArray(String fieldName)
    throws DecodingException;	
	
	public byte[] getByteString(String fieldName)
    throws DecodingException;	
	
	public byte[][] getByteStringArray(String fieldName)
    throws DecodingException;	
	
	public NodeId getNodeId(String fieldName)
    throws DecodingException;	
	
	public NodeId[] getNodeIdArray(String fieldName)
    throws DecodingException;	
	
	public ExpandedNodeId getExpandedNodeId(String fieldName)
    throws DecodingException;	
	
	public ExpandedNodeId[] getExpandedNodeIdArray(String fieldName)
    throws DecodingException;	
	
	public StatusCode getStatusCode(String fieldName)
    throws DecodingException;	
	
	public StatusCode[] getStatusCodeArray(String fieldName)
    throws DecodingException;	
	
	public QualifiedName getQualifiedName(String fieldName)
    throws DecodingException;	
	
	public QualifiedName[] getQualifiedNameArray(String fieldName)
    throws DecodingException;	
	
	public LocalizedText getLocalizedText(String fieldName)
    throws DecodingException;	
	
	public LocalizedText[] getLocalizedTextArray(String fieldName)
    throws DecodingException;	
	
	public Structure getStructure(String fieldName)
    throws DecodingException;	
	
	public Structure[] getStructureArray(String fieldName)
    throws DecodingException;	
	
	public DataValue getDataValue(String fieldName)
    throws DecodingException;	
	
	public DataValue[] getDataValueArray(String fieldName)
    throws DecodingException;	
	
	public Variant getVariant(String fieldName)
    throws DecodingException;	
	
	public Variant[] getVariantArray(String fieldName)
    throws DecodingException;	
	
	public DiagnosticInfo getDiagnosticInfo(String fieldName)
    throws DecodingException;
	
	public DiagnosticInfo[] getDiagnosticInfoArray(String fieldName)
    throws DecodingException;	
	
	public <T extends Enumeration> T[] getEnumerationArray(String fieldName, Class<T> enumerationClass)
    throws DecodingException;	
	
	public <T extends Enumeration> T getEnumeration(String fieldName, Class<T> enumerationClass)
    throws DecodingException;	
	
	public <T extends IEncodeable> T[] getEncodeableArray(String fieldName, Class<? extends T> encodeableClass)
    throws DecodingException;	
	
	public <T extends IEncodeable> T getEncodeable(String fieldName, Class<? extends T> encodeableClass)
    throws DecodingException;	
	
	public <T extends IEncodeable> T getMessage()
    throws DecodingException;	
	
	public Object getScalarObject(String fieldName, int builtinTypeId)
    throws DecodingException;	
	
	public Object getArrayObject(String fieldName, int builtinTypeId)
    throws DecodingException;	
	
}
