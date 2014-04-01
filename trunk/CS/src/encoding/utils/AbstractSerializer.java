package encoding.utils;

import java.util.Collection;

import builtintypes.NodeId;
import encoding.DecodingException;
import encoding.EncodeType;
import encoding.EncodingException;
import encoding.IDecoder;
import encoding.IEncodeable;
import encoding.IEncoder;
import encoding.binary.IEncodeableSerializer;

public abstract class AbstractSerializer implements IEncodeableSerializer{
	
	Class<? extends IEncodeable> clazz;
	NodeId binaryId, xmlId;
	
	public AbstractSerializer(Class<? extends IEncodeable> clazz, NodeId binaryId, NodeId xmlId)
	{
		if (clazz==null)
			throw new IllegalArgumentException("null arg");
		this.clazz = clazz;
		this.binaryId = binaryId;
		this.xmlId = xmlId;
	}
	
	public abstract void calcEncodeable(IEncodeable encodeable, IEncoder calculator)
	throws EncodingException;

	public abstract void putEncodeable(IEncodeable encodeable, IEncoder encoder) 
	throws EncodingException;
	
	public abstract IEncodeable getEncodeable(IDecoder decoder) 
	throws DecodingException;
	
	
	@Override
	public void calcEncodeable(Class<? extends IEncodeable> clazz,
			IEncodeable encodeable, IEncoder calculator)
			throws EncodingException {
		if (!clazz.equals(this.clazz))
			throw new EncodingException("Cannot encode "+clazz);
		calcEncodeable(encodeable, calculator);
	}


	@Override
	public void putEncodeable(Class<? extends IEncodeable> clazz,
			IEncodeable encodeable, IEncoder encoder) throws EncodingException
			 {
		if (!clazz.equals(this.clazz))
			throw new EncodingException("Cannot encode "+clazz);
		putEncodeable(encodeable, encoder);
	}	
	@Override
	public Class<? extends IEncodeable> getClass(NodeId id) {
		return (id.equals(binaryId) || id.equals(xmlId)) ? clazz : null; 
	}

	@Override
	public NodeId getNodeId(Class<? extends IEncodeable> clazz, EncodeType type) {
		if (type==EncodeType.Binary) return binaryId;
		if (type==EncodeType.Xml) return xmlId;
		return null; 
	}
	
	@Override
	public IEncodeable getEncodeable(Class<? extends IEncodeable> clazz,
			IDecoder decoder) throws DecodingException {
		if (!clazz.equals(this.clazz))
			throw new DecodingException("Cannot decode "+clazz);
		return getEncodeable(decoder);
	}

	@Override
	public void getSupportedClasses(Collection<Class<? extends IEncodeable>> result) {
		result.add(clazz);
	}

	@Override
	public void getSupportedNodeIds(Collection<NodeId> result) {
		if (binaryId!=null)
			result.add(binaryId);
		if (xmlId!=null)
			result.add(xmlId);
	}
}
