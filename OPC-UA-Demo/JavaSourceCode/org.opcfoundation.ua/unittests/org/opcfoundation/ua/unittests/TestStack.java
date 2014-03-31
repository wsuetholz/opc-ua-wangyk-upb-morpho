/* ========================================================================
 * Copyright (c) 2005-2010 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

package org.opcfoundation.ua.unittests;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Random;

import org.opcfoundation.ua.builtintypes.Variant;
import org.opcfoundation.ua.common.ServiceFaultException;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.TestStackRequest;
import org.opcfoundation.ua.core.TestStackResponse;
import org.opcfoundation.ua.transport.AsyncResult;
import org.opcfoundation.ua.transport.SecureChannel;
import org.opcfoundation.ua.utils.StackUtils;

/**
 * Stress test & performance test using a loop-back server.
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class TestStack extends StackTestBench {
	
	/** Timeout for a single test (Seconds) */
	final static int ITERATION_TIMEOUT = 300;
	
	public void testPerformance()
	throws ServiceResultException, InterruptedException, ServiceFaultException
	{
		int iterations = 5;
		int[] concurrentRequests = new int[] {      1000,     1000,      100,       10,      10};
		int[] msgSizes = new int[]           {         1,     1024,    10240,   102400, 1024000};

		System.out.println();
		
		for (int i=0; i<msgSizes.length; i++) {
			doTest(secureChannel, iterations, msgSizes[i], concurrentRequests[i]);
			doTest(unsecureChannel, iterations, msgSizes[i], concurrentRequests[i]);
		}		
	}
	
	private void doTest(SecureChannel c, int iterations, int msgSize, int concurrentRequests)
	throws ServiceResultException, InterruptedException, ServiceFaultException
	{
		System.out.println("Test case:");
		System.out.println(" * Concurrent Requests = "+concurrentRequests);
		System.out.println(" * Message Size = "+msgSize);
		System.out.println(" * Security Mode: "+c.getMessageSecurityMode());
		long bytes = msgSize * concurrentRequests;
		byte[] data = new byte[msgSize];
		fill(data);
		TestStackRequest testRequest = new TestStackRequest(null, null, null, new Variant(data));

		System.out.print(" * Iteration: ");
		ArrayList<Long> times = new ArrayList<Long>(); 
		for (int i=0; i<iterations; i++) {
			Runtime.getRuntime().gc();			
			AsyncResult reqs[] = new AsyncResult[concurrentRequests];
			
			long time = System.currentTimeMillis();		
			for (int j=0; j<concurrentRequests; j++) {
				reqs[j] = c.serviceRequestAsync( testRequest );
			}
			
			if (!StackUtils.barrierWait(reqs, ITERATION_TIMEOUT)) 
				fail("Test failed, Timeouted ("+ITERATION_TIMEOUT+"s)");			
			
			// Barrier wait
			time = System.currentTimeMillis() - time;
			times.add(time);
			
			// Verify all requests
			for (AsyncResult req : reqs) {
				TestStackResponse res = (TestStackResponse) req.waitForResult();
				verify((byte[]) res.getOutput().getValue());
			}
			System.out.print(".");
		}
		System.out.println();
		
		Collections.sort(times);
		long medianTime = times.get(times.size()/2);
		System.out.println(" * Median time: "+medianTime+" ms");
		System.out.println(" * Round-trip transfer rate: "+ (bytes*1000 / medianTime)/(1024) + " KB/s" );
		System.out.println("End.");
		System.out.println();			
	}	

	// Fill array with debug data
	public void fill(byte[] data)
	{
		// Create random generator with fixed seed
		Random r = new Random(data.length);
		for (int i=0; i<data.length; i++)
			data[i] = (byte) (r.nextInt(256) - 128);
	}
	
	// Verify array of debug data
	public void verify(byte[] data)
	{
		// Create random generator with the same seed
		Random r = new Random(data.length);
		for (int i=0; i<data.length; i++)
			assertEquals((byte) (r.nextInt(256) - 128), data[i]);
	}	
	
}