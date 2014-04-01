package encoding;

import core.StatusCodes;
import builtintypes.UnsignedInteger;
import builtintypes.StatusCode;
import common.ServiceResultException;

public class EncodingException extends ServiceResultException{
	private static final long serialVersionUID = 1L;

	public EncodingException() {
		super(new StatusCode(StatusCodes.Bad_EncodingError));
	}
	
	public EncodingException(Exception e) {
		super(new StatusCode(StatusCodes.Bad_EncodingError), e, e.getMessage());
	}
	
	public EncodingException(String message, Exception e) {
		super(new StatusCode(StatusCodes.Bad_EncodingError), e, message);
	}
	
	public EncodingException(String message) {
		super(new StatusCode(StatusCodes.Bad_EncodingError), message);
	}

	public EncodingException(int statusCode, String text) {
		super(statusCode, text);
		// TODO Auto-generated constructor stub
	}

	public EncodingException(int statusCode) {
		super(statusCode);
		// TODO Auto-generated constructor stub
	}

	public EncodingException(StatusCode statusCode, String text) {
		super(statusCode, text);
		// TODO Auto-generated constructor stub
	}

	public EncodingException(StatusCode statusCode, Throwable reason,
			String text) {
		super(statusCode, reason, text);
		// TODO Auto-generated constructor stub
	}

	public EncodingException(StatusCode statusCode) {
		super(statusCode);
		// TODO Auto-generated constructor stub
	}

	public EncodingException(Throwable reason) {
		super(reason);
		// TODO Auto-generated constructor stub
	}

	public EncodingException(UnsignedInteger statusCode, String text) {
		super(statusCode, text);
		// TODO Auto-generated constructor stub
	}

	public EncodingException(UnsignedInteger statusCode, Throwable reason) {
		super(statusCode, reason);
		// TODO Auto-generated constructor stub
	}

	public EncodingException(UnsignedInteger statusCode) {
		super(statusCode);
		// TODO Auto-generated constructor stub
	}
}
