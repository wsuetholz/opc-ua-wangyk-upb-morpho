package common;

import builtintypes.NodeId;
import utils.BijectionMap;
import builtintypes.ExpandedNodeId;

public class NamespaceTable {

	BijectionMap<Integer, String> indexUriMap = new BijectionMap<Integer, String>();
	
	public static String OPCUA_NAMESPACE = "http://opcfoundation.org/UA/";
	private static final long serialVersionUID = 1L;
	public static NamespaceTable createFromArray(String[] namespaceArray)
	{
		NamespaceTable result = new NamespaceTable();
		for (int i = 0; i<namespaceArray.length; i++)
			result.add(i, namespaceArray[i]);
		return result;
	}
	public static final NamespaceTable DEFAULT;
	
	static{
		DEFAULT = new NamespaceTable();
		DEFAULT.add(0,OPCUA_NAMESPACE);
	}
	
	public static NamespaceTable getDefault()
	{
		return DEFAULT;
	}
	public NodeId toNodeId(ExpandedNodeId expandedNodeId)
			throws ServiceResultException {
		// TODO: serverIndex==0 is valid reference to the local server, so it
		// should be accepted as well // jaro
		if (ExpandedNodeId.isNull(expandedNodeId))
			return NodeId.NULL;
		if (!expandedNodeId.isLocal())
			throw new ServiceResultException(
					"Cannot convert ExpandedNodeId with server index to NodeId");
		String uri = expandedNodeId.getNamespaceUri();
		if (uri == null)
			return NodeId.get(expandedNodeId.getIdType(), expandedNodeId
					.getNamespaceIndex(), expandedNodeId.getValue());
		Integer index = this.getIndex(uri);
		if (index == null)
			throw new ServiceResultException(
					"Index not found in NamespaceTable");
		return NodeId.get(expandedNodeId.getIdType(), index, expandedNodeId
				.getValue());
	}

	public synchronized String[] toArray() {
		int len = 0;
		for (Integer i : indexUriMap.getLeftSet())
			if (i > len)
				len = i;
		len++;
		String result[] = new String[len];
		for (int i = 0; i < len; i++)
			result[i] = indexUriMap.getRight(i);
		return result;
	}

	/**
	 * Finds the namespace URI with index in the table
	 * 
	 * @param namespaceIndex
	 *            the index you are looking for
	 * @return the namespace URI with the index or null, if there is no such
	 *         index
	 */
	public String getUri(int namespaceIndex) {
		return indexUriMap.getRight(namespaceIndex);
	}

	/**
	 * Finds the index of the namespace URI in the table
	 * 
	 * @param namespaceUri
	 *            the URI of the namespace you are looking for
	 * @return the index of the URI or -1, if it is not in the table
	 */
	public int getIndex(String namespaceUri) {
		Integer i = indexUriMap.getLeft(namespaceUri);
		if (i == null)
			return -1;
		return i;
	}

	/**
	 * Add a new namespace to the table.
	 * 
	 * @param index
	 *            The new index (use -1 to automatically use the next unused
	 *            index)
	 * @param namespaceUri
	 *            The namespace URI.
	 * @throws IllegalArgumentException
	 *             if the index or URI is already in the table.
	 */
	public int add(int index, String namespaceUri) {
		// check if namespaceIndex already exists
		if (getIndex(namespaceUri) >= 0)
			return getIndex(namespaceUri);
		if (index < 0)
			index = nextIndex();
		else if (getUri(index) != null)
			throw new IllegalArgumentException(
					"namespaceTable already has namespaceIndex " + index);
		// in other case we are able to add new namespaceIndex with value
		indexUriMap.map(index, namespaceUri);
		return index;
	}

	private int nextIndex() {
		int result = -1;
		for (int i : indexUriMap.getLeftSet())
			if (i > result)
				result = i;
		return result + 1;
	}

	/**
	 * Remove the entry for the specified namespaceIndex
	 * 
	 * @param namespaceIndex
	 */
	public void remove(int namespaceIndex) {
		indexUriMap.removeWithLeft(namespaceIndex);
	}

	/**
	 * Remove the entry for the specified namespaceUri
	 * 
	 * @param namespaceUri
	 */
	public void remove(String namespaceUri) {
		indexUriMap.removeWithRight(namespaceUri);
	}

	
	
}
