package core;

import utils.ObjectUtils;
import builtintypes.DateTime;
import builtintypes.NodeId;
import core.Identifiers;
import builtintypes.StatusCode;

public class ResponseHeader extends Object implements Cloneable{
	
	public static final NodeId ID = Identifiers.ResponseHeader;
	public static final NodeId BINARY = Identifiers.ResponseHeader_Encoding_DefaultBinary;
	public static final NodeId XML = Identifiers.ResponseHeader_Encoding_DefaultXml;	
	
	protected DateTime Timestamp;
	protected int RequestHandle;
	protected StatusCode ServiceResult;
	protected String[] StringTable;
	//protected DiagnosticInfo ServiceDiagnostics;
	
	public ResponseHeader(){}
	
	public void RespsonseHeader(DateTime Timestamp, int RequestHandle, StatusCode ServiceResult, String[] StringTable)
	{
		this.Timestamp = Timestamp;
		this.RequestHandle = RequestHandle;
		this.ServiceResult = ServiceResult;
		this.StringTable = StringTable;
	}
	
	   public DateTime getTimestamp()
	    {
	        return Timestamp;
	    }
	    
	    public void setTimestamp(DateTime Timestamp)
	    {
	        this.Timestamp = Timestamp;
	    }
	    
	    public int getRequestHandle()
	    {
	        return RequestHandle;
	    }
	    
	    public void setRequestHandle(int RequestHandle)
	    {
	        this.RequestHandle = RequestHandle;
	    }
	    
	    public StatusCode getServiceResult()
	    {
	        return ServiceResult;
	    }
	    
	    public void setServiceResult(StatusCode ServiceResult)
	    {
	        this.ServiceResult = ServiceResult;
	    }
	    
	    
	    public String[] getStringTable()
	    {
	        return StringTable;
	    }
	    
	    public void setStringTable(String[] StringTable)
	    {
	        this.StringTable = StringTable;
	    }
	    
	    
	    /**
	      * Deep clone
	      *
	      * @return cloned ResponseHeader
	      */
	    public ResponseHeader clone()
	    {
	        ResponseHeader result = new ResponseHeader();
	        result.Timestamp = Timestamp;
	        result.RequestHandle = RequestHandle;
	        result.ServiceResult = ServiceResult;
	        result.StringTable = StringTable==null ? null : StringTable.clone();
	        return result;
	    }
	    


		public NodeId getTypeId() {
			return ID;
		}

		public NodeId getXmlEncodeId() {
			return XML;
		}

		public NodeId getBinaryEncodeId() {
			return BINARY;
		}
		
		public String toString() {
			return "ResponseHeader: "+ObjectUtils.printFieldsDeep(this);
		}

}
