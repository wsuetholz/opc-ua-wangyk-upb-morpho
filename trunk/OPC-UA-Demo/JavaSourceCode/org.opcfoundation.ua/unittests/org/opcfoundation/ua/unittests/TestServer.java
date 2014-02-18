package org.opcfoundation.ua.unittests;

import org.opcfoundation.ua.application.Server;
import org.opcfoundation.ua.builtintypes.ServiceRequest;
import org.opcfoundation.ua.transport.EndpointServiceRequest;

public class TestServer extends StackTestBench {
	@SuppressWarnings("unchecked")
	public void testDiscovery() {
		Server server1 = new Server();
		Server server2 = new Server();
		Object handler1 = server1.getServiceHandlerByService((Class<? extends ServiceRequest>) EndpointServiceRequest.class);
		Object handler2 = server2.getServiceHandlerByService((Class<? extends ServiceRequest>) EndpointServiceRequest.class);
		assertSame("endpointserviceHandler", handler1, handler2);

	}
}
