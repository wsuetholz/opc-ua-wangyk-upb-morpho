package builtintypes;

import builtintypes.StatusCode;

public class ServiceResult<Throawble> {
	
	private StatusCode code;
	private String symbolicId;
	private String addtionalInfo;
	private ServiceResult innnerResult;
	
	public ServiceResult()
	{
		initialize();
	}
	
	public ServiceResult(StatusCode code)
	{
		initialize(code);
	}
	public boolean isBad()
	{
		if (code ==null) return false;
		return code.isBad();
	}
	public void initialize()
	{
		initialize(StatusCode.GOOD, null);
	}
	public void initialize(StatusCode code)
	{
		this.code = code;
	}
	public void initialize (StatusCode code, String e)
	{
		this.code = code;
		this.addtionalInfo = e;		
	}

	public void setCode(StatusCode statusCode) {
		// TODO Auto-generated method stub
		this.code = statusCode;
	}

	public void setSymbolicId(String string) {
		// TODO Auto-generated method stub
		this.symbolicId = string;
	}

	public void setAdditionalInfo(String string) {
		// TODO Auto-generated method stub
		this.addtionalInfo = string;
	}
	
	
}
