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

package org.opcfoundation.ua.examples;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;

import org.apache.log4j.PropertyConfigurator;
import org.opcfoundation.ua.application.Client;
import org.opcfoundation.ua.application.SessionChannel;
import org.opcfoundation.ua.builtintypes.LocalizedText;
import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.core.Attributes;
import org.opcfoundation.ua.core.BrowseDescription;
import org.opcfoundation.ua.core.BrowseDirection;
import org.opcfoundation.ua.core.BrowseResponse;
import org.opcfoundation.ua.core.BrowseResultMask;
import org.opcfoundation.ua.core.Identifiers;
import org.opcfoundation.ua.core.NodeClass;
import org.opcfoundation.ua.core.ReadResponse;
import org.opcfoundation.ua.core.ReadValueId;
import org.opcfoundation.ua.core.TimestampsToReturn;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.PrivKey;
import org.opcfoundation.ua.utils.CertificateUtils;

/**
 * Sample client creates a connection to OPC Server (1st arg), browses and reads a bit. 
 * e.g. opc.tcp://localhost:51210/
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class SampleClient {


	public static final Locale ENGLISH = Locale.ENGLISH;
	public static final Locale ENGLISH_FINLAND = new Locale("en", "FI");
	public static final Locale ENGLISH_US = new Locale("en", "US");

	public static final Locale FINNISH = new Locale("fi");
	public static final Locale FINNISH_FINLAND = new Locale("fi", "FI");
	
	public static final Locale GERMAN = Locale.GERMAN;
	public static final Locale GERMAN_GERMANY = new Locale("de", "DE");
	
	public static void main(String[] args) 
	throws Exception {
		if (args.length==0) {
			System.out.println("Usage: SampleClient [server uri]");
			return;
		}
		URI uri = new URI( args[0] );
		System.out.print("SampleClient: Connecting to "+uri+" .. ");
		
		// Load Log4j configurations from external file
		PropertyConfigurator.configure( SampleClient.class.getResource("log.properties") );
		
		EnumSet<NodeClass> e = EnumSet.of(NodeClass.Object, NodeClass.View);
		
		//////////////  CLIENT  //////////////
		// Create Client
		Client myClient = new Client();
		myClient.addLocale( FINNISH_FINLAND );
		myClient.addLocale( ENGLISH_FINLAND );
		myClient.addLocale( ENGLISH );
		myClient.setApplicationName( new LocalizedText("Java Sample Client", Locale.ENGLISH) );
		myClient.setProductUri( "JavaSampleClient" );
		myClient.addApplicationInstanceCertificate( loadOrCreateCertificate() );		

		// Connect to the given uri
		SessionChannel mySession = myClient.createSessionChannel(uri);
//		mySession.activate("username", "123");
		mySession.activate();
		//////////////////////////////////////		
		
		/////////////  EXECUTE  //////////////		
		// Browse Root
		BrowseDescription browse = new BrowseDescription();
		browse.setNodeId( Identifiers.RootFolder );
		browse.setBrowseDirection( BrowseDirection.Forward );
		browse.setIncludeSubtypes( true );
		browse.setNodeClassMask( NodeClass.Object, NodeClass.Variable );
		browse.setResultMask( BrowseResultMask.All );
		BrowseResponse res3 = mySession.Browse( null, null, null, browse );				
		System.out.println(res3);

		// Read Namespace Array
		ReadResponse res5 = mySession.Read(
			null, 
			null, 
			TimestampsToReturn.Neither, 				
			new ReadValueId(Identifiers.Server_NamespaceArray, Attributes.Value, null, null ) 
		);
		String[] namespaceArray = (String[]) res5.getResults()[0].getValue().getValue();
		System.out.println(Arrays.toString(namespaceArray));
		
		// Read a variable
		ReadResponse res4 = mySession.Read(
			null, 
			500.0, 
			TimestampsToReturn.Source, 
			new ReadValueId(new NodeId(6, 1710), Attributes.Value, null, null ) 
		);		
		System.out.println(res4);
		
		res4 = mySession.Read(
			null, 
			500.0, 
			TimestampsToReturn.Source, 
			new ReadValueId(new NodeId(6, 1710), Attributes.DataType, null, null ) 
		);		
		System.out.println(res4);
		
		
		/////////////  SHUTDOWN  /////////////
		mySession.close();
		mySession.closeAsync();
		//////////////////////////////////////	
		
	}

	/**
	 * In the first run this method creates public&private key pair and saves them to files.
	 * In other runs the key pairs are loaded from files.
	 * 
	 * @return
	 * @throws Exception
	 */
    public static KeyPair loadOrCreateCertificate() 
    throws Exception
    {
    	File certFile = new File( "SampleClient.der" ); 
    	File privFile = new File( "SampleClient.key" );
    	try {
    		Cert cert = Cert.load(certFile);
    		PrivKey privKey = PrivKey.load(privFile);
			return new KeyPair(cert, privKey);
		} catch (IOException e) {
		}
    	List<String> hostnameList = new ArrayList<String>();
    	hostnameList.add("My Hostname");
		KeyPair result = CertificateUtils.createApplicationInstanceCertificate("Java Sample Client", "Early Adopter Test Organisation", java.net.InetAddress.getLocalHost().getHostName(), 365);
			//CertificateUtils.generateKeyPair("SampleClient");
		result.save(certFile, privFile);
		return result;
    }
	
}
