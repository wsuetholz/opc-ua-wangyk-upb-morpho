package common;

import java.util.Arrays;

import builtintypes.ServiceResult;
import builtintypes.StatusCode;
import builtintypes.UnsignedInteger;
import core.StatusCodes;

/**
 * Generic Exception
 * 
 */

public class ServiceResultException extends Exception {

    private static final long serialVersionUID = 988605552235028178L;

    final protected StatusCode statusCode;
    final protected String text;

    public ServiceResultException(String message)
    {
    	this(new StatusCode(StatusCodes.Bad_Error),  message);
    }
    
    public ServiceResultException(int statusCode)
    {
        this(StatusCode.getFromBits(statusCode), StatusCodeDescriptions.getStatusCodeDescription(statusCode));
    }

    public ServiceResultException(int statusCode, String text)
    {
        this(StatusCode.getFromBits(statusCode), text);
    }
    
    public ServiceResultException(UnsignedInteger statusCode)
    {
        this(new StatusCode(statusCode), StatusCodeDescriptions.getStatusCodeDescription(statusCode.intValue()));
    }

    public ServiceResultException(UnsignedInteger statusCode, String text)
    {
        this(new StatusCode(statusCode), text);
    }    

    public ServiceResultException(UnsignedInteger statusCode, Throwable reason, String text)
    {
    	super(text, reason);
        if (statusCode==null)
            throw new IllegalArgumentException("statusCode is null");        
        this.statusCode = new StatusCode(statusCode);
        this.text = text;        
    }    
    
    public ServiceResultException(StatusCode statusCode)
    {
        this(statusCode, statusCode.getDescription()!=null ? statusCode.getDescription() : "");
    }

    public ServiceResultException(StatusCode statusCode, String text)
    {
        if (statusCode==null)
            throw new IllegalArgumentException("statusCode is null");
        this.statusCode = statusCode;
        this.text = text;
    }

    public ServiceResultException(StatusCode statusCode, Throwable reason, String text)
    {
    	super(text, reason);
        if (statusCode==null)
            throw new IllegalArgumentException("statusCode is null");        
        this.statusCode = statusCode;
        this.text = text;        
    }

    public ServiceResultException(UnsignedInteger statusCode, Throwable reason)
    {
    	super(reason.getMessage(), reason);
        if (statusCode==null)
            throw new IllegalArgumentException("statusCode is null");        
        this.statusCode = new StatusCode(statusCode);
        this.text = statusCode.toString() + ", " + reason.getMessage();        
    }
    
    public ServiceResultException(StatusCode statusCode, Throwable reason)
    {
    	super(reason.getMessage(), reason);
        if (statusCode==null)
            throw new IllegalArgumentException("statusCode is null");        
        this.statusCode = statusCode;
        this.text = statusCode.toString() + ", " + reason.getMessage();        
    }

    public ServiceResultException(Throwable reason)
    {
    	super(reason);
        this.statusCode = new StatusCode(StatusCodes.Bad_UnexpectedError);
        this.text = reason.getMessage();        
    }
    
    @Override
    public String getMessage() {
        if (text!=null)
            return String.format("%s (code=0x%08X, description=\"%s\")", statusCode.getName(), statusCode.getValueAsIntBits(), text);
        return statusCode.toString();
    }
    
    public StatusCode getStatusCode() {
        return statusCode;
    }
        
    public String getAdditionalTextField()
    {
        return text;
    }
    
    /**
     * Converts the error into a service result
     * 
     * @return a new service result object
     */
    public ServiceResult toServiceResult()
    {
    	ServiceResult res = new ServiceResult();
    	if (statusCode==null)
    		res.setCode(new StatusCode(StatusCodes.Bad_UnexpectedError));
    	else
    		res.setCode(statusCode);
    	res.setSymbolicId(statusCode.toString());
    	res.setAdditionalInfo(Arrays.toString(getStackTrace()));
    	return res;
    }
        
}
