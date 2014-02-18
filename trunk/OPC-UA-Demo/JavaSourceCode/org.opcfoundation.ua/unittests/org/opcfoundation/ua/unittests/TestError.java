package org.opcfoundation.ua.unittests;

import org.opcfoundation.ua.builtintypes.StatusCode;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.CreateSessionRequest;
import org.opcfoundation.ua.core.StatusCodes;

public class TestError extends StackTestBench {

	public void testServiceUnsupported() {
		try {
			unsecureChannel.serviceRequest(new CreateSessionRequest());
			fail("Expected ServiceResultException");
		} catch (ServiceResultException e) {
			assertEquals(new StatusCode(StatusCodes.Bad_ServiceUnsupported), e
					.getStatusCode());
		}
	}
}
