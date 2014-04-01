package encoding;

import common.ServiceResultException;
import builtintypes.StatusCode;
import builtintypes.UnsignedInteger;
import core.StatusCodes;

public class DecodingException extends ServiceResultException{
	private static final long serialVersionUID = 1L;

	public DecodingException() {
		super(StatusCodes.Bad_DecodingError);
	}
	
	public DecodingException(Exception e) {
		super(StatusCodes.Bad_DecodingError, e, e.getMessage());
	}
	
	public DecodingException(Exception e, String message) {
		super(StatusCodes.Bad_DecodingError, e, message);
	}
	
	public DecodingException(Throwable reason) {
		super(reason);
		// TODO Auto-generated constructor stub
	}

	public DecodingException(UnsignedInteger statusCode, Throwable reason) {
		super(statusCode, reason);
		// TODO Auto-generated constructor stub
	}

	public DecodingException(String message, Exception e) {
		super(StatusCodes.Bad_DecodingError, e, message);
	}

	public DecodingException(String message) {
		super(StatusCodes.Bad_DecodingError, message);
	}

	public DecodingException(int statusCode, String text) {
		super(statusCode, text);
		// TODO Auto-generated constructor stub
	}

	public DecodingException(int statusCode) {
		super(statusCode);
		// TODO Auto-generated constructor stub
	}

	public DecodingException(StatusCode statusCode, String text) {
		super(statusCode, text);
		// TODO Auto-generated constructor stub
	}

	public DecodingException(StatusCode statusCode, Throwable reason,
			String text) {
		super(statusCode, reason, text);
		// TODO Auto-generated constructor stub
	}

	public DecodingException(StatusCode statusCode) {
		super(statusCode);
		// TODO Auto-generated constructor stub
	}

	public DecodingException(UnsignedInteger statusCode, String text) {
		super(statusCode, text);
		// TODO Auto-generated constructor stub
	}

	public DecodingException(UnsignedInteger statusCode) {
		super(statusCode);
		// TODO Auto-generated constructor stub
	}

}
