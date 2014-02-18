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

import java.util.concurrent.ConcurrentHashMap;

import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.Identifiers;
import org.opcfoundation.ua.core.StatusCodes;

public class Jotakin {

	public static void main(String[] args) throws Exception {
		
//		NodeId id = Identifiers.toNodeId("TwoStateDiscreteType");
//		System.out.println(id);
		

//		ConcurrentHashMap<String, Integer> map = new ConcurrentHashMap<String, Integer>();
//		map.put("x", 1);
//		map.put("y", 2);
//		map.put("z", 3);
//		
//		for (String s : map.keySet()) {
//			System.out.println(s);
//			map.remove(s);
//		}
		
		
//		// Test COW, iterator, remove
//		CopyOnWriteArrayList<String> cow = new CopyOnWriteArrayList<String>();
//		cow.add("123");
//		cow.add("234");
//		cow.add("435");
//		cow.add("vvk");
//		cow.add("000");
//		for (String s : cow)
//			cow.remove(s);
		
//		try
//		{
//			throw new Exception();
//		} catch (Exception e) {
//			System.out.println("e");
//		} finally {
//			System.out.println("f");
//		}
//		
//        throw new ServiceResultException(
//                StatusCodes.Bad_SecurityPolicyRejected, 
//                "Unsupported asymmetric signature algorithm: {0}, "+ 
//                "XYZ");
		
//		System.out.println( String.format("0x%08x", 0x506070) );
		
//		try {
//			throw new IllegalArgumentException();
//		} catch (IllegalArgumentException e) {
//			throw new RuntimeException();
//		} catch (RuntimeException e) {
//			System.out.println("sfd");
//			e.printStackTrace();
//		}
		
//		ServiceResultException se = new ServiceResultException(StatusCodes.Bad_Timeout, "hassua tapahtui");
//		System.out.println(se.toString());
//		
//		InetSocketAddress addr = InetSocketAddress.createUnresolved("localhost", 6000);
//		System.out.println(addr.toString());
//		
//		EndpointDescription ed = new EndpointDescription();
//		ed.setUserIdentityTokens( new UserTokenPolicy[] {new UserTokenPolicy("xyz", null, null, null, null)} );
//		
//		System.out.println(ed);
//		
//		EndpointDescription ed2 = ed.clone();
//		System.out.println(ed2);
		
//		Object array[] = new Object[] {"a", "b", "c", "d", new LinkedList()};
//		Object array2[] = (Object[]) MultiDimensionArrayUtils.clone(array);		
//		Object array3[] = (Object[]) MultiDimensionArrayUtils.deepClone(array);		
//		Object array4[] = array.clone();		
//		System.out.println(Arrays.toString(array2));
//		System.out.println(Arrays.toString(array3));
//		System.out.println(Arrays.toString(array4));
		
//		final ServerSocket ss = new ServerSocket(605);
//		new Thread() {
//			public void run() {
//				try {
//					Socket sss = ss.accept();
//					System.out.println("accepted");
//					Thread.sleep(1000);					
//					sss.close();
//					System.out.println("closed.");
////					System.out.println("Writing");
////					sss.getOutputStream().write(6);					
//				} catch (IOException e) {
//					e.printStackTrace();
//				} catch (InterruptedException e) {
//					e.printStackTrace();
//				}
//			};
//		}.start();
//		Socket s = new Socket("localhost", 605);
//		s.setSoTimeout(10000);
//		System.out.println("reading");
////		while (s.getInputStream().available()==0);
////		s.getInputStream().read();
////		System.out.println("read");
//		s.getInputStream().read();
//		System.out.println("read");
		
		
		
//		Throwable t = new Exception();
//		ServiceFault f = ServiceFault.toServiceFault(t);
//		System.out.println(new ServiceFaultException(f));
//		
//		System.out.println("\n\n\n\n\n");
//		
//		t = new ServiceResultException(StatusCodes.Bad_ArgumentsMissing, t);
//		f = ServiceFault.toServiceFault(t);
//		System.out.println(new ServiceFaultException(f));
		
		
	}
	
}
