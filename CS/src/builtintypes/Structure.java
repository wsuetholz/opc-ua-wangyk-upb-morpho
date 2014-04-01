package builtintypes;

import encoding.IEncodeable;

/**
 * Super interface for all complex type serializable objects
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public interface Structure extends IEncodeable {

	NodeId getTypeId();
	NodeId getXmlEncodeId();
	NodeId getBinaryEncodeId();
	
}