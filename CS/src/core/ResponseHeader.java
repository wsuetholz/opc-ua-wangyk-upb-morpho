package core;

import utils.ObjectUtils;
import builtintypes.DateTime;
import builtintypes.DiagnosticInfo;
import builtintypes.NodeId;
import builtintypes.UnsignedInteger;
import core.Identifiers;
import builtintypes.StatusCode;

public class ResponseHeader extends Object implements Cloneable{
	
	public static final NodeId ID = Identifiers.ResponseHeader;
	public static final NodeId BINARY = Identifiers.ResponseHeader_Encoding_DefaultBinary;
	public static final NodeId XML = Identifiers.ResponseHeader_Encoding_DefaultXml;	
	
    protected DateTime Timestamp;
    protected UnsignedInteger RequestHandle;
    protected StatusCode ServiceResult;
    protected DiagnosticInfo ServiceDiagnostics;
    protected String[] StringTable;
	//protected DiagnosticInfo ServiceDiagnostics;
	
	public ResponseHeader(){}
	
	public void RespsonseHeader(DateTime Timestamp, UnsignedInteger RequestHandle, StatusCode ServiceResult, DiagnosticInfo ServiceDiagnostics, String[] StringTable)
	{
	    this.Timestamp = Timestamp;
        this.RequestHandle = RequestHandle;
        this.ServiceResult = ServiceResult;
        this.ServiceDiagnostics = ServiceDiagnostics;
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
	    
	    public UnsignedInteger getRequestHandle()
	    {
	        return RequestHandle;
	    }
	    
	    public void setRequestHandle(UnsignedInteger RequestHandle)
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
	    
	    public DiagnosticInfo getServiceDiagnostics()
	    {
	        return ServiceDiagnostics;
	    }
	    
	    public void setServiceDiagnostics(DiagnosticInfo ServiceDiagnostics)
	    {
	        this.ServiceDiagnostics = ServiceDiagnostics;
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
	        result.ServiceDiagnostics = ServiceDiagnostics;
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
