package encoding;

import common.NamespaceTable;
import common.ServerTable;
import utils.StackUtils;
import encoding.binary.IEncodeableSerializer;
import utils.StackUtils;

public class EncoderContext {

	private static EncoderContext DEFAULT;
	
	public NamespaceTable namespaceTable;
	public ServerTable serverTable;
	public IEncodeableSerializer encodeableSerializer;
	
	public int maxMessageSize = 4*1024*1024*1024;
	
	public int maxStringLength = 0;
	public int maxByteStringLength = 0;
	public int maxArrayLength = 0;
	
	public EncoderContext()
	{
		
	}
	
	public EncoderContext(NamespaceTable namespaceTable, ServerTable serverTable,
						IEncodeableSerializer encodeableSerializer, int maxMessageSize)
	{
		this.encodeableSerializer = encodeableSerializer;
		this.namespaceTable = namespaceTable;
		this.serverTable = serverTable;
		this.maxMessageSize = maxMessageSize;
	}
	
	public int getMaxMessageSize()
	{
		return maxMessageSize;
	}
	
	public void setMaxMessageSize(int encodeMessageSize)
	{
		this.maxMessageSize = encodeMessageSize;
	}
	public NamespaceTable getNamespaceTable()
	{
		return namespaceTable;
	}
	public void setNamespaceTable(NamespaceTable namespaceTable)
	{
		this.namespaceTable = namespaceTable;
	}
	public ServerTable getServerTable() {
		return serverTable;
	}

	public void setServerTable(ServerTable serverTable) {
		this.serverTable = serverTable;
	}

	public IEncodeableSerializer getEncodeableSerializer() {
		return encodeableSerializer;
	}

	public void setEncodeableSerializer(IEncodeableSerializer encodeableSerializer) {
		this.encodeableSerializer = encodeableSerializer;
	}
	
	public int getMaxStringLength() {
		return maxStringLength;
	}

	public void setMaxStringLength(int maxStringLength) {
		this.maxStringLength = maxStringLength;
	}

	public int getMaxByteStringLength() {
		return maxByteStringLength;
	}

	public void setMaxByteStringLength(int maxByteStringLength) {
		this.maxByteStringLength = maxByteStringLength;
	}

	public int getMaxArrayLength() {
		return maxArrayLength;
	}

	public void setMaxArrayLength(int maxArrayLength) {
		this.maxArrayLength = maxArrayLength;
	}

	public synchronized static EncoderContext getDefault()
	{
		if (DEFAULT==null) {
			DEFAULT = new EncoderContext();
			DEFAULT.setServerTable(ServerTable.DEFAULT);
			DEFAULT.setNamespaceTable(NamespaceTable.DEFAULT);
			DEFAULT.setEncodeableSerializer(StackUtils.getDefaultSerializer());
		}
		return DEFAULT;
	}
}
