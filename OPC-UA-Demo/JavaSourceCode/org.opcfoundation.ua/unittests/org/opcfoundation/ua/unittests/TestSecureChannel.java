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
import java.io.IOException;

import junit.framework.TestCase;

import org.apache.log4j.PropertyConfigurator;
import org.opcfoundation.ua.builtintypes.Variant;
import org.opcfoundation.ua.common.NamespaceTable;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.EndpointConfiguration;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.TestStackRequest;
import org.opcfoundation.ua.encoding.IEncodeable;
import org.opcfoundation.ua.examples.Example1;
import org.opcfoundation.ua.transport.AsyncResult;
import org.opcfoundation.ua.transport.ResultListener;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.CertificateValidator;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.PrivKey;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.transport.tcp.io.SecureChannelTcp;
import org.opcfoundation.ua.transport.tcp.io.TransportChannelSettings;

// (c) Copyright 2009 The OPC Foundation
// ALL RIGHTS RESERVED.
//
// DISCLAIMER:
//  This code is provided by the OPC Foundation solely to assist in 
//  understanding and use of the appropriate OPC Specification(s) and may be 
//  used as set forth in the License Grant section of the OPC Specification.
//  This code is provided as-is and without warranty or support of any sort
//  and is subject to the Warranty and Liability Disclaimers which appear
//  in the printed OPC Specification.
//
// Authors:
//  VTT Technical Research Centre of Finland (www.vtt.fi)
//  Tampere University of Technology (www.tut.fi)
//  Prosys (www.prosys.fi) 
//  Wapice (www.wapice.fi) 
//  Metso Automation (www.metsoautomation.com) 
//  Kone (www.kone.com)

public class TestSecureChannel extends TestCase {

	public void testOpen() throws ServiceResultException, IOException {
		// Load Log4j configurations from external file
		PropertyConfigurator.configure( TestSecureChannel.class.getResource("log.properties") );
		
		// Test open with wrong proto
		TransportChannelSettings settings = new TransportChannelSettings();
		
		Cert myClientCertificate = Cert.load( Example1.class.getResource( "ClientCert.der" ) );
		PrivKey myClientPrivateKey = PrivKey.loadFromKeyStore( Example1.class.getResource( "ClientCert.pfx"), "Opc.Sample.Ua.Client");
		KeyPair myClientApplicationInstanceCertificate = new KeyPair(myClientCertificate, myClientPrivateKey);
						
		EndpointDescription ed = new EndpointDescription();
		// 51210 = C#, 4841 = C, 4840 = Discover //
		ed.setEndpointUrl("opc.tcp://localhost:51210"); // C#  
//		ed.setEndpointUrl("opc.tcp://localhost:4841");  // C  
//		ed.setEndpointUrl("opc.tcp://ESPVM3K280:5001"); // Remote C#
		
		// No security
		ed.setSecurityMode(MessageSecurityMode.None);
		ed.setSecurityPolicyUri(SecurityPolicy.NONE.getPolicyUri());

		// SEcurity
//		ed.setSecurityMode(MessageSecurityMode.SignAndEncrypt);
//		ed.setSecurityPolicyUri(SecurityPolicy.BASIC128RSA15.getPolicyUri());
				
		EndpointConfiguration ec = EndpointConfiguration.defaults();
//		ec.setSecurityTokenLifetime(2000);
//		ec.setSecurityTokenLifetime(10000);
		
		settings.setConfiguration(ec);
		settings.setClientCertificate( myClientCertificate );
		settings.setNamespaceUris( NamespaceTable.DEFAULT );
		settings.setPrivKey( myClientPrivateKey );
		settings.getClientCertificate();		
		settings.setCertificateValidator( CertificateValidator.ALLOW_ALL );
		settings.setDescription( ed );

		SecureChannelTcp channel = new SecureChannelTcp();		
		channel.initialize(settings);
		channel.open();
		channel.setOperationTimeout(1);
		try {

			TestStackRequest req = new TestStackRequest();
			req.setInput(new Variant("Moi"));
			
//			TestStackResponse res = (TestStackResponse) channel.sendRequest( req );
									
			
			for (int i = 0; i<4; i++) {
				
				try { Thread.sleep(2000); } catch (InterruptedException e) {}
				
				try {
					System.out.print( "SyncRequest .. " );
					IEncodeable result = channel.serviceRequest( req );
					System.out.println( result.getClass().getSimpleName() );
				} catch (ServiceResultException e) {
					System.err.println(e.getMessage());
				}

				try { Thread.sleep(2000); } catch (InterruptedException e) {}
				
//				System.out.println( "AsyncRequest" );
				AsyncResult res = channel.serviceRequestAsync( req );
				res.setListener( new ResultListener() {
					@Override
					public void onCompleted(Object result) {
						System.out.print( "AsyncRequest .. " );
						System.out.println( result.getClass().getSimpleName() );
					}
					@Override
					public void onError(ServiceResultException e) {
						System.out.print( "AsyncRequest .. " );
						System.out.println(e.getMessage());
					}});
				
			}
		} finally {
			
			channel.close();
			channel.dispose();
			try {
				Thread.sleep(5000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}	
		
	}
	
}
