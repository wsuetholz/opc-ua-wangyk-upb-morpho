/* ========================================================================
 * Copyright (c) 2005-2010 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Reciprocal Community License ("RCL") Version 1.00
 * 
 * Unless explicitly acquired and licensed from Licensor under another 
 * license, the contents of this file are subject to the Reciprocal 
 * Community License ("RCL") Version 1.00, or subsequent versions as 
 * allowed by the RCL, and You may not copy or use this file in either 
 * source code or executable form, except in compliance with the terms and 
 * conditions of the RCL.
 * 
 * All software distributed under the RCL is provided strictly on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, 
 * AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT 
 * LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RCL for specific 
 * language governing rights and limitations under the RCL.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/RCL/1.00/
 * ======================================================================*/

package transport;

import java.io.EOFException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.Selector;
import java.util.Random;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import builtintypes.UnsignedInteger;
import common.ServiceResultException;
import core.EncodeableSerializer;
import core.StatusCodes;
import encoding.binary.EncodeableReflectionSerializer;
import encoding.binary.IEncodeableSerializer;
import encoding.utils.EncodeableDesc;
import encoding.utils.EncodeableDescTable;
import encoding.utils.SerializerComposition;
import transport.AsyncResult;
import transport.ResultListener;
import transport.AsyncResult.AsyncResultStatus;
import transport.tcp.impl.Acknowledge;
import transport.tcp.impl.ErrorMessage;
import transport.tcp.impl.Hello;
import utils.asyncsocket.AsyncSelector;

/**
 *
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class StackUtils {

	/**
	 * The default thread factory
	 */
	static class NamedThreadFactory implements ThreadFactory {
	    static final AtomicInteger poolNumber = new AtomicInteger(1);
	    final ThreadGroup group;
	    final AtomicInteger threadNumber = new AtomicInteger(1);
	    final String namePrefix;
	
	    NamedThreadFactory(String name) {
	        SecurityManager s = System.getSecurityManager();
	        group = (s != null)? s.getThreadGroup() :
	                             Thread.currentThread().getThreadGroup();
	        namePrefix = name+"-pool-" +
	                      poolNumber.getAndIncrement() +
	                     "-thread-";
	    }
	
	    public Thread newThread(Runnable r) {
	        Thread t = new Thread(group, r,
	                              namePrefix + threadNumber.getAndIncrement(),
	                              0);
	        if (t.isDaemon())
	            t.setDaemon(false);
	        if (t.getPriority() != Thread.NORM_PRIORITY)
	            t.setPriority(Thread.NORM_PRIORITY);
	        return t;
	    }
	}

	public static final int CORES = Runtime.getRuntime().availableProcessors();
	public static Executor NON_BLOCKING_EXECUTOR;
	public static Executor BLOCKING_EXECUTOR;
	public static AsyncSelector SELECTOR;
	public static Random RANDOM = new Random();
	
	/** Requested token lifetime */
	public static final UnsignedInteger CLIENT_TOKEN_LIFETIME_REQUEST = new UnsignedInteger(600000);
	/** Maximum lifetime server is willing to offer */
	public static final UnsignedInteger SERVER_GIVEN_TOKEN_LIFETIME = UnsignedInteger.getFromBits(600*1000);
	
	public static final int TCP_PROTOCOL_VERSION = 0;

	private static IEncodeableSerializer DEFAULT_SERIALIZER;

	/**
	 * Get encodeable serializer
	 * 
	 * @return encodeable serialier
	 */
	public synchronized static IEncodeableSerializer getDefaultSerializer()
	{
		if (DEFAULT_SERIALIZER==null) {
			SerializerComposition serializer;
			// Option A) Codegenerated Serialiser
			serializer = EncodeableSerializer.getInstance();
			
			// Option B) Reflection Serializer
//			serializer = new SerializerComposition();			
//			serializer.addSerializer( EncodeableReflectionSerializer.getDefault() );
			
			
			// Add acknowledge/hello/errormessage to the selected serializer
			EncodeableDescTable reflectionTable = new EncodeableDescTable();
			reflectionTable.addStructureInfo( EncodeableDesc.readFromClass(Acknowledge.class) );
			reflectionTable.addStructureInfo( EncodeableDesc.readFromClass(Hello.class) );
			reflectionTable.addStructureInfo( EncodeableDesc.readFromClass(ErrorMessage.class) );			
			EncodeableReflectionSerializer e = new EncodeableReflectionSerializer(reflectionTable);
			
			serializer.addSerializer(e);			
			
			DEFAULT_SERIALIZER = serializer;
		}
		return DEFAULT_SERIALIZER;
	}	

	/**
	 * Get Executor for non-blocking operations.  
	 * This executor has one thread for one core in the system.
	 * 
	 * @return Executor that executes non-blocking short term operations. 
	 */
	public static synchronized Executor getNonBlockingWorkExecutor() {
		if (NON_BLOCKING_EXECUTOR == null) {
			final ThreadGroup tg = new ThreadGroup("Non-Blocking-Work-Executor-Group");
			final AtomicInteger counter = new AtomicInteger(0);
			ThreadFactory tf = new ThreadFactory() {
				@Override
				public Thread newThread(Runnable r) {
					Thread t = new Thread(tg, r, "Non-Blocking-Work-Executor-"+(counter.incrementAndGet()));
					t.setDaemon(true);
					return t;
				}};
			NON_BLOCKING_EXECUTOR = //new ScheduledThreadPoolExecutor( CORES );
				new ThreadPoolExecutor(
						CORES, 
						CORES,
                        3L, TimeUnit.SECONDS,
                        new LinkedBlockingQueue<Runnable>(),
                        tf);			
		}
		return NON_BLOCKING_EXECUTOR;
	}
	
	/**
	 * Get Executor for long term and potentially blocking operations.
	 * 
	 * @return executor for blocking operations
	 */
	public static synchronized Executor getBlockingWorkExecutor() {
		if (BLOCKING_EXECUTOR == null) {
			final ThreadGroup tg = new ThreadGroup("Blocking-Work-Executor-Group");
			final AtomicInteger counter = new AtomicInteger(0);
			ThreadFactory tf = new ThreadFactory() {
				@Override
				public Thread newThread(Runnable r) {
					Thread t = new Thread(tg, r, "Blocking-Work-Executor-"+(counter.incrementAndGet()));
					t.setDaemon(true);
					return t;
				}};
				BLOCKING_EXECUTOR = 
				new ThreadPoolExecutor(
						0, 
						Integer.MAX_VALUE,
                        3L, TimeUnit.SECONDS,
                        new SynchronousQueue<Runnable>(),
                        tf);			
		}
		return BLOCKING_EXECUTOR;
	}
	
	
	public static ServiceResultException toServiceResultException(Exception e)
	{
		if (e instanceof ServiceResultException)
			return (ServiceResultException) e;
		if (e instanceof ClosedChannelException)
			return new ServiceResultException(StatusCodes.Bad_ConnectionClosed, e);
		if (e instanceof EOFException)
			return new ServiceResultException(StatusCodes.Bad_ConnectionClosed, e, "Connection closed (graceful)");
		if (e instanceof ConnectException)
			return new ServiceResultException(StatusCodes.Bad_ConnectionRejected, e);
		if (e instanceof SocketException)
			return new ServiceResultException(StatusCodes.Bad_ConnectionClosed, e, "Connection closed (unexpected)");
		if (e instanceof IOException)
			return new ServiceResultException(StatusCodes.Bad_UnexpectedError, e);
		return new ServiceResultException(e);
	}
	
	public static int cores() {
		return CORES;
	}

	/**
	 * Wait for a group to requests to go into final state
	 * 
	 * @param requests a group of requests
	 * @param timeout timeout in seconds
	 * @return true if completed ok
	 * @throws InterruptedException
	 */
	public static boolean barrierWait(AsyncResult[] requests, long timeout)
	throws InterruptedException
	{
		final Semaphore sem = new Semaphore(0);
		
		ResultListener l = new ResultListener() {
			@Override
			public void onCompleted(Object result) {
				sem.release();
			}

			@Override
			public void onError(ServiceResultException error) {
				sem.release();
			}};
		
		for (AsyncResult r : requests) {
			synchronized(r) {
				if (r.getStatus() != AsyncResultStatus.Waiting)
					sem.release();
				else
					r.setListener(l);
			}			
		}
		
		return sem.tryAcquire(requests.length, timeout, TimeUnit.SECONDS); 
	}
	
	static {
		try {
			SELECTOR = new AsyncSelector(Selector.open());
		} catch (IOException e) {
			throw new Error(e);
		}
	}

	public static ThreadFactory newNamedThreadFactory(String name) {
		return new NamedThreadFactory(name);
	}
	
}
