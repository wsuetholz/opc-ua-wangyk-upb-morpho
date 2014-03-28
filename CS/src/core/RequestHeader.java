package core;

import builtintypes.NodeId;
import builtintypes.DateTime;
import core.Identifiers;
import utils.ObjectUtils;

public class RequestHeader extends Object implements Cloneable{
	
	public static final NodeId ID = Identifiers.RequestHeader;
	public static final NodeId BINARY = Identifiers.RequestHeader_Encoding_DefaultBinary;
	public static final NodeId XML = Identifiers.RequestHeader_Encoding_DefaultXml;	
	
	protected NodeId AuthenticationToken ;
	protected DateTime Timestamp;
	protected int RequestHandle;
	protected int ReturnDiagnostics;
	protected String AuditEntryId;
	protected int TimeoutHint;
	
	public RequestHeader(){}
	
	public RequestHeader(NodeId AuthenticationToken, DateTime Timestamp, int RequestHandle, int ReturnDiagnostics, String AuditEntryId, int TimeoutHint)
	{
		this.AuthenticationToken = AuthenticationToken;
		this.Timestamp = Timestamp;
		this.RequestHandle = RequestHandle;
		this.ReturnDiagnostics = ReturnDiagnostics;
		this.AuditEntryId = AuditEntryId;
		this.TimeoutHint = TimeoutHint;
	}
	
	public NodeId getAuthenticationToken()
	{
		return this.AuthenticationToken;
	}
	public void setAuthenticatonToken(NodeId AuthenticationToken)
	{
		this.AuthenticationToken = AuthenticationToken;
	}
	public DateTime getTimestamp()
	{
		return this.Timestamp;
	}
	public void setTimestamp(DateTime Timestamp)
	{
		this.Timestamp = Timestamp;
	}
	public int getRequestHandle()
	{
		return  this.RequestHandle;
	}
	public void setReturnDiagnostics(int ReturnDiagnostics)
	{
		 this.ReturnDiagnostics = ReturnDiagnostics;
	}
	public int setReturnDiagnostics()
	{
		return this.ReturnDiagnostics;
	}
	public void setAuditEntryId(String AuditEntryId)
	{
		this.AuditEntryId = AuditEntryId;
	}
	public String getAuditEntryId()
	{
		return this.AuditEntryId;
	}
	public void setTimeoutHint(int TimeoutHint)
	{
		this.TimeoutHint = TimeoutHint;
	}
	public int getTimeoutHint()
	{
		return this.TimeoutHint;
	}
    public RequestHeader clone()
    {
        RequestHeader result = new RequestHeader();
        result.AuthenticationToken = AuthenticationToken;
        result.Timestamp = Timestamp;
        result.RequestHandle = RequestHandle;
        result.ReturnDiagnostics = ReturnDiagnostics;
        result.AuditEntryId = AuditEntryId;
        result.TimeoutHint = TimeoutHint;
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
		return "RequestHeader: "+ObjectUtils.printFieldsDeep(this);
	}
}
