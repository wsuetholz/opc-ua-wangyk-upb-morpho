package builtintypes;

import core.Identifiers;
import core.IdType;

import java.lang.IllegalArgumentException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.UUID;

public final class NodeId {
	
	public static final NodeId Zero = new NodeId(0,UnsignedInteger.getFromBits(0));
	public static final NodeId NULL = Zero;
	public static final NodeId NULL_NUMERIC = new NodeId(0,UnsignedInteger.getFromBits(0));
	IdType type;
	final int namespaceIndex;
	final Object value;
	int hashCode;
	
	public static final NodeId ID = Identifiers.NodeId;
	

	public static NodeId get(IdType type, int namespaceIndex, Object value)
	{
		if (type == IdType.Numeric) {
			return new NodeId(namespaceIndex, (UnsignedInteger) value);
			}
		throw new IllegalArgumentException("Bad Type");
	
	}
	public NodeId(int namespaceIndex, int value) {
		// TODO Auto-generated constructor stub
		this(namespaceIndex, UnsignedInteger.getFromBits(value));
	}
	
	public NodeId(int namespaceIndex, UnsignedInteger value)
	{
		if (value == null) throw new IllegalArgumentException("Numeric NodeId cannot be null");
		if (namespaceIndex<0 || namespaceIndex>65535) 
			throw new IllegalArgumentException("namespaceIndex out of bounds");		
		this.value = value;
		this.namespaceIndex = namespaceIndex;
		hashCode += 13*namespaceIndex + value.hashCode();
		type = IdType.Numeric;
	}
	
	public boolean isNullNodeId() {
		if (this.value == null)
			return true;
		// Note: equals checks for IsNull, so we cannot use equals
		switch (this.type) {
		case Numeric:
			return this.value.equals(NULL_NUMERIC.value);

		default:
			return false;
		}
	}
	
	/**
	 * Check if nodeId is null or a NullNodeId.
	 * @param nodeId
	 * @return true if (nodeId == null) || nodeId.isNullNodeId()
	 */
	public static boolean isNull(NodeId nodeId) {
		return (nodeId == null) || nodeId.isNullNodeId();
	}
	
	public IdType getIdType()
	{
		return type;
	}
		
	/**
	 * 
	 * @return the value, UnsignedInteger, UUID, String, byte[], or null (null opaque) 
	 */
	public Object getValue()
	{
		return value;
	}
	
	public int getNamespaceIndex()
	{
		return namespaceIndex;
	}
	@Override
	public int hashCode() {
		return hashCode;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return isNull(this);
		if (obj instanceof NodeId) {
			NodeId other = (NodeId) obj;
			if (isNull(this) || isNull(other)) return isNull(this) == isNull(other); //handle null
			if (other.namespaceIndex!=namespaceIndex || other.type!=type) return false;
			if (this.value==other.value) return true;		
			return other.value.equals(value);
		} else
		return false;
	}
	
	@Override
	public String toString() {
		String nsPart = namespaceIndex>0 ? "ns="+namespaceIndex+";" : "";
		if (type == IdType.Numeric) return nsPart + "i="+value;	
		return "error";
	}
	
	/**
	 * Convert String representation to NodeId.
	 * If the namespace is expressed with URI, then the
	 * <t>namespaceTable</t> field is required.
	 * 
	 * The String representation is in the following notations:
	 *  ns=[id];i=[number]
	 *  i=[number]
	 *  
	 *  ns=[id];s=[string]
	 *  s=[string]
	 *  
	 *  ns=[id];g=[guid]
	 *  g=[guid]
	 *  	
	 *  ns=[id];b=[base64]
	 *  b=[base64]
	 * 
	 * @param nodeIdRef
	 * @return nodeid
	 * @throws IllegalArgumentException
	 * @throws NamespaceNotFoundException
	 */
	public static NodeId decode(String nodeIdRef)
	throws IllegalArgumentException
	{
		if (nodeIdRef==null) throw new IllegalArgumentException("null arg");
		
		Matcher m;
		
		m = NONE_STRING.matcher(nodeIdRef);
		if (m.matches()) {			
			String obj = m.group(1);
			return new NodeId(0,obj);
		}
		
		m = NONE_INT.matcher(nodeIdRef);
		if (m.matches()) {			
			Integer obj = Integer.valueOf( m.group(1) );
			return new NodeId(0,obj);
		}
	
		
		throw new IllegalArgumentException("Invalid string representation of a nodeId");
	}
	
	static final Pattern INT_INT = Pattern.compile("ns=(\\d*);i=(\\d*)");	
	static final Pattern NONE_INT = Pattern.compile("i=(\\d*)");	

	static final Pattern INT_STRING = Pattern.compile("ns=(\\d*);s=(.*)");	
	static final Pattern NONE_STRING = Pattern.compile("s=(.*)");	
	
	static final Pattern INT_GUID = Pattern.compile("ns=(\\d*);g=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");	
	static final Pattern NONE_GUID = Pattern.compile("g=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");	

	static final Pattern INT_OPAQUE = Pattern.compile("ns=(\\d*);b=([0-9a-zA-Z\\+/=]*)");	
	static final Pattern NONE_OPAQUE = Pattern.compile("b=([0-9a-zA-Z\\+/=]*)");
	
	
	
}
