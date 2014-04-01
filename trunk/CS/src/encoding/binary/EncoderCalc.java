package encoding.binary;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Iterator;
import java.util.UUID;

import builtintypes.BuiltinsMap;
import builtintypes.UnsignedInteger;
import builtintypes.NodeId;
import builtintypes.Enumeration;
import builtintypes.StatusCode;
import builtintypes.DateTime;
import builtintypes.UnsignedByte;
import builtintypes.ExpandedNodeId;
import encoding.EncodingException;
import core.IdType;
import encoding.EncodeType;
import encoding.EncoderContext;
import encoding.EncodingException;
import encoding.IEncodeable;
import encoding.IEncoder;
import encoding.utils.EncodeableDesc;
import utils.MultiDimensionArrayUtils;



public class EncoderCalc implements IEncoder {

	static ThreadLocal<EncoderCalc> calculator = new ThreadLocal<EncoderCalc>();
		
	EncoderContext ctx; 
	int length;

	public EncoderCalc() 
	{		
	}
	
	public int getLength()
	{
		return length;
	}
	
	public void reset()
	{
		length = 0;
	}
	
	public int getAndReset()
	{
		int result = length;
		length = 0;
		return result;
	}

	public EncoderContext getEncoderContext() {
		return ctx;
	}

	public void setEncoderContext(EncoderContext ctx) {
		this.ctx = ctx;
	}
	
	public void putBoolean(String fieldName, Boolean v)
	{
		length++;
	}

	public void putBooleanArray(String fieldName, Boolean[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + v.length;
	}	
	
	public void putBooleanArray(String fieldName, Collection<Boolean> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + v.size();
	}	
	
	public void putSByte(String fieldName, Byte v)
	{
		length += 1;
	}
	
	public void putSByte(String fieldName, byte v)
	{
		length += 1;
	}

	public void putSByte(String fieldName, int v)
	{
		length += 1;
	}

	public void putSByteArray(String fieldName, Byte[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + v.length;
	}
	
	public void putSByteArray(String fieldName, Collection<Byte> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + v.size();
	}
	
	public void putInt16(String fieldName, Short v)
	{
		length += 2;
	}

	public void putInt16(String fieldName, short v)
	{
		length += 2;
	}
	
	public void putInt16Array(String fieldName, Short[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 2*v.length;
	}	
	
	public void putInt16Array(String fieldName, Collection<Short> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 2*v.size();
	}	
	
	
	public void putInt32(String fieldName, Integer v)
	{
		length += 4;
	}
	
	public void putInt32(String fieldName, int v)
	{
		length += 4;
	}
	
	public void putInt32Array(String fieldName, int[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 4*v.length;
	}
	public void putInt32Array(String fieldName, Collection<Integer> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 4*v.size();
	}	
	
	public void putInt32Array(String fieldName, Integer[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 4*v.length;
	}
		
	public void putUInt32(String fieldName, UnsignedInteger v)
	{
		length += 4;
	}
	
	public void putUInt32Array(String fieldName, UnsignedInteger[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 4*v.length;
	}	
	
	public void putUInt32Array(String fieldName, Collection<UnsignedInteger> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 4*v.size();
	}	
	
	public void putInt64(String fieldName, Long v)
	{
		length += 8;
	}
	
	public void putInt64(String fieldName, long v)
	{
		length += 8;
	}	
	
	public void putInt64Array(String fieldName, Long[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 8*v.length;
	}
	
	public void putInt64Array(String fieldName, Collection<Long> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 8*v.size();
	}
	
	public void putFloat(String fieldName, Float v)
	{
		length += 4;
	}
	
	public void putFloat(String fieldName, float v)
	{
		length += 4;
	}
	
	public void putFloatArray(String fieldName, Float[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 4*v.length;
	}
	
	public void putFloatArray(String fieldName, Collection<Float> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 4*v.size();
	}		
		
	public void putDouble(String fieldName, Double v)
	{
		length += 8;
	}
	
	public void putDouble(String fieldName, double v)
	{
		length += 8;
	}
	
	public void putDoubleArray(String fieldName, Double[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 8*v.length;
	}	
	
	public void putDoubleArray(String fieldName, Collection<Double> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 8*v.size();
	}	
	
	
	public void putDateTime(String fieldName, DateTime v)
	{
		length += 8;
	}

	public void putDateTimeArray(String fieldName, DateTime[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 8*v.length;
	}			
	
	public void putDateTimeArray(String fieldName, Collection<DateTime> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 8*v.size();
	}			
	
	public void putGuid(String fieldName, UUID v)
	{
		length += 16;
	}
	
	public void putGuidArray(String fieldName, UUID[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 16*v.length;
	}			
	
	public void putGuidArray(String fieldName, Collection<UUID> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 16*v.size();
	}			
	
	public void putByteString(String fieldName, byte[] v)
	{
		if (v==null) 
			length += 4;
		else {
			length += 4 + v.length;
		}		
	}
	
	public void putByteStringArray(String fieldName, byte[][] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4;
		for (int i=0; i<v.length; i++)
			putByteString(null, v[i]);
	}				
	
	public void putByteStringArray(String fieldName, Collection<byte[]> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4;
		for (byte[] o : v)
			putByteString(null, o);
	}				
	
	
	public void putNodeId(String fieldName, NodeId v)
	{
		if (v==null) v = NodeId.NULL; 
		
		Object o = v.getValue();
		if (v.getIdType() == IdType.Numeric) {
			UnsignedInteger i = (UnsignedInteger) o;
			if (i.compareTo(UnsignedByte.MAX_VALUE)<=0 && v.getNamespaceIndex()==0)
			{
				length += 2;
			} else 
			 {
				length += 7;
			}
		}
			
	}
	
	public void putNodeIdArray(String fieldName, NodeId[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4;
		for (int i=0; i<v.length; i++)
			putNodeId(null, v[i]);
	}		

	public void putNodeIdArray(String fieldName, Collection<NodeId> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4;
		for (NodeId o : v)
			putNodeId(null, o);
	}		
	
	public void putExpandedNodeId(String fieldName, ExpandedNodeId v)
	{
		if (v==null) v = ExpandedNodeId.NULL;
		
		byte upperBits = 0;
		if (v.getNamespaceUri()!=null) upperBits |= 0x80;
		if (v.getServerIndex()!=null) upperBits |= 0x40;
		
		Object o = v.getValue();
		if (v.getIdType() == IdType.Numeric) {
			UnsignedInteger i = (UnsignedInteger) o;
			if (i.compareTo(UnsignedByte.MAX_VALUE)<=0 && v.getNamespaceIndex()==0)
			{
				length += 2;
			} else 
			{
				length += 7;
			}
		}
			
		if (v.getServerIndex()!=null) {
			length += 4;
		}
	}
	
	public void putExpandedNodeIdArray(String fieldName, ExpandedNodeId[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4;
		for (int i=0; i<v.length; i++)
			putExpandedNodeId(null, v[i]);
	}		

	public void putExpandedNodeIdArray(String fieldName, Collection<ExpandedNodeId> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4;
		for (ExpandedNodeId o : v)
			putExpandedNodeId(null, o);
	}		
	
	public void putStatusCode(String fieldName, StatusCode v)
	{
		length += 4;
	}
	
	public void putStatusCodeArray(String fieldName, StatusCode[] v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 4*v.length;
	}		
	
	public void putStatusCodeArray(String fieldName, Collection<StatusCode> v)
	{
		if (v==null) {
			length += 4;
			return;
		}
		
		length += 4 + 4*v.size();
	}		
	

	
	public void putEnumerationArray(String fieldName, Object array)
	{
		if (array==null) {
			length += 4;
			return;
		}
		int len = Array.getLength(array);
		length += 4;
		for (int i=0; i<len; i++)
			putEnumeration(null, (Enumeration)Array.get(array, i));
	}
	
	public void putEnumeration(String fieldName, Enumeration v)
	{
		//if (v==null)
			//throw new EncodingException("Cannot encode null value");
		length += 4;
	}

	public void putObject(String fieldName, Object o) throws EncodingException
	{
		if (o==null) throw new EncodingException("Cannot encode null value");
		Class<?> c = o.getClass();
		putObject(null, c, o);
	}
	
	@SuppressWarnings("unchecked")
	public void putObject(String fieldName, Class<?> c, Object o) throws EncodingException
	{
		Integer bt = BuiltinsMap.ID_MAP.get(c);
		boolean array = c.isArray() && !c.equals(byte[].class);
		if (bt!=null) {
			if (array) 
				putArray(null, bt, o);
			else
				putScalar(null, bt, o);
			return;
		} 
		
		if (!array && Enumeration.class.isAssignableFrom(c)) {
			putEnumeration(null, (Enumeration)o);
			return;
		}

		if (array && Enumeration.class.isAssignableFrom(c.getComponentType())) {
			putEnumerationArray(null, o);
			return;
		}
		
		Class<?> scalarClass = array ? c.getComponentType() : c; 
		if (array)
			putEncodeableArray(null, (Class<? extends IEncodeable>) scalarClass, o);
		else
			ctx.encodeableSerializer.calcEncodeable((Class<? extends IEncodeable>) scalarClass, (IEncodeable)o, this);
	}
	
	/**
	 * Guess builtin type
	 * @param builtinType
	 * @return -1 unknown, other builting scalar size
	 */
	int guessBuiltinSize(int builtinType)
	{
		switch (builtinType) {
		case 1: return 1; 
		case 2: return 1; 
		case 3: return 1; 
		case 4: return 2; 
		case 5: return 2; 
		case 6: return 4; 
		case 7: return 4; 
		case 8: return 8; 
		case 9: return 8; 
		case 10: return 4; 
		case 11: return 8; 
		case 13: return 8; 
		case 14: return 16;
		case 19: return 4;
		default: return -1; 
		}		
	}
	
	public void putScalar(String fieldName, int builtinType, Object o) throws EncodingException
	{
		switch (builtinType) {
		case 1: putBoolean(null, (Boolean) o); break;
		case 2: putSByte(null, (Byte) o); break;
		case 4: putInt16(null, (Short) o); break;
		case 6: putInt32(null, (Integer) o); break;
		case 7: putUInt32(null, (UnsignedInteger) o); break;
		case 8: putInt64(null, (Long) o); break;
		case 10: putFloat(null, (Float) o); break;
		case 11: putDouble(null, (Double) o); break;
		case 13: putDateTime(null, (DateTime) o); break;
		case 14: putGuid(null, (UUID) o); break;
		case 15: putByteString(null, (byte[]) o); break;
		case 17: putNodeId(null, (NodeId) o); break;
		case 18: putExpandedNodeId(null, (ExpandedNodeId) o); break;
		case 19: putStatusCode(null, (StatusCode) o); break;
		default: throw new EncodingException("cannot encode builtin type "+builtinType); 
		}
	}
	
	public void putArray(String fieldName, int builtinType, Object o) throws EncodingException
	{
		switch (builtinType) {
		case 1: putBooleanArray(null, (Boolean[]) o); break;
		case 2: putSByteArray(null, (Byte[]) o); break;
		case 4: putInt16Array(null, (Short[]) o); break;
		case 6: putInt32Array(null, (Integer[]) o); break;
		case 7: putUInt32Array(null, (UnsignedInteger[]) o); break;
		case 8: putInt64Array(null, (Long[]) o); break;
		case 10: putFloatArray(null, (Float[]) o); break;
		case 11: putDoubleArray(null, (Double[]) o); break;
		case 13: putDateTimeArray(null, (DateTime[]) o); break;
		case 14: putGuidArray(null, (UUID[]) o); break;
		case 15: putByteStringArray(null, (byte[][]) o); break;
		case 17: putNodeIdArray(null, (NodeId[]) o); break;
		case 18: putExpandedNodeIdArray(null, (ExpandedNodeId[]) o); break;
		case 19: putStatusCodeArray(null, (StatusCode[]) o); break;
		default: throw new EncodingException("cannot encode builtin type "+builtinType); 
		}
	}	
	
	public void putEncodeableArray(String fieldName, Class<? extends IEncodeable> clazz, Object array) throws ArrayIndexOutOfBoundsException, EncodingException, IllegalArgumentException
	{
		if (array==null) {
			length += 4;
			return;
		}
		int len = Array.getLength(array);
		length += 4;
		for (int i=0; i<len; i++) 
			ctx.encodeableSerializer.calcEncodeable(clazz, (IEncodeable)Array.get(array, i), this);
	}
	
	/**
	 * Encodes stucture without header
	 * @param s
	 * @throws EncodingException 
	 */
	@SuppressWarnings("unchecked")
	public void putEncodeable(String fieldName, IEncodeable s) throws EncodingException
	{		
		Class<IEncodeable> clazz			= (Class<IEncodeable>) s.getClass();
		ctx.encodeableSerializer.calcEncodeable(clazz, s, this);		
	}

	/**
	 * Encodes stucture without header
	 * @param s
	 * @throws EncodingException 
	 */
	public void putEncodeable(String fieldName, Class<? extends IEncodeable> clazz, IEncodeable s) throws EncodingException
	{		
		ctx.encodeableSerializer.calcEncodeable(clazz, s, this);		
	}
	
	/**
	 * Encodes stucture without header
	 * @param s
	 * @throws EncodingException 
	 */
	void putEncodeable(String fieldName, IEncodeable s, EncodeableDesc si) throws EncodingException
	{		
		try {
			for (EncodeableDesc.FieldInfo fi : si.fields)
			{
				Field f					= fi.field;
				Object value			= s==null ? null : f.get(s);
				putObject(null, fi.type, value);
			}
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}	

	/**
	 * Encodes structures including header (typeId, encoding type and length)
	 * @param s
	 * @throws EncodingException 
	 */
//	@SuppressWarnings("unchecked")
//	public void putStructure(IEncodeable s)
//	{
//		Class<IEncodeable> clazz = (Class<IEncodeable>) s.getClass();
//		if (!encodeableSerializer.getEncodeSet().contains(clazz))
//			throw new EncodingException("Cannot decode "+clazz);
//
//		length += 5;
//		encodeableSerializer.putMessage(s, encoder)
//		putNodeId(si.binaryId);
//		putEncodeable(s, si);
//	}
	
	@SuppressWarnings("unchecked")
	public void putMessage(IEncodeable s) throws EncodingException
	{
		Class<IEncodeable> clazz = (Class<IEncodeable>) s.getClass();
		putNodeId(null, ctx.encodeableSerializer.getNodeId(clazz, EncodeType.Binary));
		ctx.encodeableSerializer.calcEncodeable(clazz, s, this);
	}

	public void popNamespace() {
		// TODO Auto-generated method stub
		
	}

	public void pushNamespace(String namespaceUri) {
		// TODO Auto-generated method stub
		
	}
	
	@Override
	public String toString() {
		return length+"";
	}

	@Override
	public void pushNameSpace(String namespaceUri) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void popNameSpace() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void putBooleanArry(String fieldName, Boolean[] v)
			throws EncodingException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void puttByte(String filedName, Byte v) throws EncodingException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void putByteArray(String fieldName, Byte[] v)
			throws EncodingException {
		// TODO Auto-generated method stub
		
	}

	
}
