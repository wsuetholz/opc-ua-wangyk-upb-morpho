package encoding.binary;

import java.util.Collection;

import builtintypes.NodeId;
import core.EncodeableSerializer;
import encoding.EncodingException;
import encoding.DecodingException;
import encoding.EncodeType;
import encoding.IDecoder;
import encoding.IEncodeable;
import encoding.IEncoder;
import encoding.utils.SerializerComposition;

public interface IEncodeableSerializer {

	void getSupportedNodeIds(Collection<NodeId> result);
	void getSupportedClasses(Collection<Class<? extends IEncodeable>> result);
	Class<? extends IEncodeable> getClass(NodeId id);
	NodeId getNodeId(Class<? extends IEncodeable> clazz, EncodeType type);
	IEncodeable getEncodeable(Class<? extends IEncodeable> clazz, IDecoder decoder)
	throws DecodingException;
	
	void putEncodeable(Class<? extends IEncodeable> clazz, IEncodeable encodeable, IEncoder encoder)
	throws EncodingException;
	
	void calcEncodeable(Class<? extends IEncodeable> clazz, IEncodeable encodeable, IEncoder calculator)
	throws EncodingException;
}
