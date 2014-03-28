package transport;

import application.Server;
import builtintypes.ServiceRequest;
import builtintypes.ServiceResponse;
import builtintypes.ServiceResult;

public abstract class EndpointServiceRequest<Request extends ServiceRequest, Response extends ServiceResponse> {
	
	Server server;
	Endpoint endpoint;
	Request request;
	
	public Request getRequest()
	{
		return request;
	}
	
	public Server getServer()
	{
		return server;
	}
	
	public Endpoint getEndpoint()
	{
		return endpoint;
	}
	


		
}
