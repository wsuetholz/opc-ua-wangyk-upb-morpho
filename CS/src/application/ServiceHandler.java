package application;

import java.util.Collection;

import builtintypes.ServiceRequest;
import builtintypes.ServiceResponse;
import encoding.IEncodeable;
import transport.EndpointServiceRequest;

public interface ServiceHandler {
	
	void serve(EndpointServiceRequest<?,?> request);
	
	boolean supportsService(Class<? extends IEncodeable> requestMessageClass);
	
	void getSupportedServices(Collection<Class<? extends IEncodeable>> result);
}
