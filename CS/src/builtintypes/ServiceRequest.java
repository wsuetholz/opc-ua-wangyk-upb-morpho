package builtintypes;

import core.RequestHeader;

public interface ServiceRequest{
	RequestHeader getRequestHeader();	
	void setRequestHeader(RequestHeader RequestHeader);
}
