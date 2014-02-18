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

package org.opcfoundation.ua.utils.asyncsocket;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.opcfoundation.ua.utils.StackUtils;
import org.opcfoundation.ua.utils.asyncsocket.AsyncSelector.SelectListener;

/**
 * ListenableServerSocketChannel adds convenient listening mechanism over
 * non-blocking ServerSocketChannel.  
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class ListenableServerSocketChannel {

	ServerSocketChannel				channel;
	AsyncSelector					selector;
	Executor						executor;
	ServerSocketAcceptable			acceptableListener;
	boolean							acceptableHndPending = false;

	public ListenableServerSocketChannel() 
	throws IOException
	{
		this(
			(ServerSocketChannel) ServerSocketChannel.open().configureBlocking(false),
	        new ThreadPoolExecutor(
	        		0, 
	        		1,
                    5L, TimeUnit.SECONDS,
                    new LinkedBlockingQueue<Runnable>(),
                    StackUtils.newNamedThreadFactory("listen1")),
        	new AsyncSelector()                    
		);
	}
	
	public ListenableServerSocketChannel(ServerSocketChannel channel) 
	throws IOException
	{
		this(
			channel,
	        new ThreadPoolExecutor(
	        		0, 
	        		1,
                    5L, TimeUnit.SECONDS,
                    new LinkedBlockingQueue<Runnable>(),
                    StackUtils.newNamedThreadFactory("listen2")),
        	new AsyncSelector()                    
		);
	}
	
	public ListenableServerSocketChannel(Executor eventExecutor) 
	throws IOException
	{
		this((ServerSocketChannel) ServerSocketChannel.open().configureBlocking(false), eventExecutor, new AsyncSelector());
	}
	
	public ListenableServerSocketChannel(ServerSocketChannel channel, Executor eventExecutor) 
	throws IOException
	{
		this(channel, eventExecutor, new AsyncSelector());
	}

	/**
	 * Wrap AsyncServerSocket over given ServerSocketChannel using given event worker thread and selector thread.  
	 *  
	 * @param channel
	 * @param eventExecutor event executor or null for selector thread
	 * @param t selector thread
	 * @throws ClosedChannelException
	 */
	public ListenableServerSocketChannel(ServerSocketChannel channel, Executor eventExecutor, AsyncSelector t) 
	throws ClosedChannelException
	{
		if (channel.isBlocking())
			throw new IllegalArgumentException("channel arg must be in non-blocking mode. (SocketChannel.configureBlocking(false))");
		if (t==null)
			throw new IllegalArgumentException("null arg");
		this.executor = eventExecutor;
		this.channel = channel;
		this.selector = t;
		t.register(ListenableServerSocketChannel.this.channel, 0, selectListener);		
	}
	
	Runnable acceptRun;

	SelectListener selectListener = new SelectListener() {
		@Override
		public void onSelected(AsyncSelector sender, SelectableChannel channel, int ops, int oldOps) {
			if ((ops & SelectionKey.OP_ACCEPT)!=0) {
				Runnable r = acceptRun;
				if (r!=null) {
					if (executor==null) {
						acceptableHndPending = true;
						try {
							r.run();
						} catch(Throwable t) {
							t.printStackTrace();
						}
					} else {
						acceptableHndPending = true;
						executor.execute( r );
					}
				}
			}
			sender.interestOps(channel, getInterestOps());
		}
	};		
	
	public void setAcceptableListener(final ServerSocketAcceptable listener)
	{
		synchronized(this) {
			this.acceptableListener = listener;
			if (listener!=null) {
				acceptRun = new Runnable() {
					@Override
					public void run() {
						try {
							listener.onConnectionAcceptable(ListenableServerSocketChannel.this);
						} finally {
							acceptableHndPending = false;
							updateInterestOps();
						}
					}
				};
			} else {
				acceptRun = null;
			}
		}
		updateInterestOps();
	}
	
	public ServerSocketAcceptable getAcceptableListener()
	{
		return acceptableListener;
	}	
	
	void updateInterestOps() {
		selector.interestOps(channel, getInterestOps());
	}
	
	synchronized int getInterestOps() {
		if (!channel.isOpen() || !channel.isRegistered()) return 0;
		int ops = 0;		
		if (acceptableListener!=null && !acceptableHndPending) ops |= SelectionKey.OP_ACCEPT;
		return ops;
	}			
	
	public interface ServerSocketAcceptable 
	{
		void onConnectionAcceptable(ListenableServerSocketChannel socket);
	}	
	
	public ServerSocketChannel getChannel()
	{
		return channel;
	}
	
	public AsyncSelector getSelectorThread()
	{
		return selector;
	}	
	
	public synchronized void close() throws IOException
	{
		if (channel==null)
			return;
		selector.unregister(channel);
		try {
			channel.close();
		} finally {
			channel = null;
		}
	}
	
   /**
    *
    * Binds the <code>ServerSocket</code> to a specific address
    * (IP address and port number).
    * <p>
    * If the address is <code>null</code>, then the system will pick up
    * an ephemeral port and a valid local address to bind the socket.
    * <P>
    * The <code>backlog</code> argument must be a positive
    * value greater than 0. If the value passed if equal or less
    * than 0, then the default value will be assumed.
    * @param	addr		The IP address & port number to bind to.
    * @param	backlog		TCP/IP Server Socket (accept queue) backlog length.
    * @throws	IOException if the bind operation fails, or if the socket
    *			   is already bound.
    * @throws	SecurityException	if a <code>SecurityManager</code> is present and
    * its <code>checkListen</code> method doesn't allow the operation.
    * @throws  IllegalArgumentException if endpoint is a
    *          SocketAddress subclass not supported by this socket
    */
	public synchronized void bind(SocketAddress addr, int backlog) 
	throws IOException
	{				
		channel.socket().bind( addr, backlog );
//		selector.unregister(channel);
		selector.register(channel, SelectionKey.OP_ACCEPT, selectListener);		
	}
		
}
