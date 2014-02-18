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

package org.opcfoundation.ua.examples;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Locale;

import org.apache.log4j.PropertyConfigurator;
import org.opcfoundation.ua.application.Client;
import org.opcfoundation.ua.application.SessionChannel;
import org.opcfoundation.ua.builtintypes.LocalizedText;
import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.builtintypes.QualifiedName;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
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
		myClient.addLocale( LocalizedText.FINNISH_FINLAND );
		myClient.addLocale( LocalizedText.ENGLISH_FINLAND );
		myClient.addLocale( Locale.ENGLISH );
		myClient.setApplicationName( new LocalizedText("Java Sample Client", Locale.ENGLISH) );
		myClient.setProductUri( "JavaSampleClient" );
		myClient.addApplicationInstanceCertificate( loadOrCreateCertificate() );		

		// Connect to the given uri
		SessionChannel mySession = myClient.createSessionChannel(uri);
		mySession.activate("username", "123");
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
		mySession.closeSession();
		mySession.closeSecureChannel();
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
		KeyPair result = CertificateUtils.generateKeyPair("SampleClient");
		result.save(certFile, privFile);
		return result;
    }
	
}

