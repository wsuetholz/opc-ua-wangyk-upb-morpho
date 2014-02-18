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

package org.opcfoundation.ua.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Random;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.SignatureData;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.PrivKey;
import org.opcfoundation.ua.transport.security.SecurityConstants;


/**
 * This is class for generating self-signed certificates for UA clients and servers.
 * At the moment it this class is under development, but one can generate CertificateKeyPair using 
 * the generateKeyPair method.
 * @author Mikko Salonen (mikko.k.salonen@tut.fi)
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi) 
 */
public class CertificateUtils {
	
	 private static Logger logger = Logger.getLogger(CertificateUtils.class);
	/**
	 * Sign data
	 * 
	 * @param signerKey
	 * @param algorithmUri asymmetric signer algorithm, See {@link SecurityConstants}
	 * @param dataToSign
	 * @return signature data 
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 * @throws NoSuchAlgorithmException 
	 */
	public static SignatureData sign(PrivateKey signerKey, String algorithmUri, byte[] dataToSign) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
		if (algorithmUri==null) return new SignatureData(null, null);
		
        if (dataToSign == null || signerKey==null)
        	throw new IllegalArgumentException("null arg");

		Signature signer = CryptoUtil.getAsymmetricSignature(algorithmUri);
		signer.initSign(signerKey);
		signer.update(dataToSign);
		byte[] signature = signer.sign();
        return new SignatureData(algorithmUri, signature);
	}
	
	/**
	 * Verify a signature
	 * 
	 * @param certificate
	 * @param algorithmUri asymmetric signer algorithm, See {@link SecurityConstants}
	 * @param data
	 * @param signature
	 * @return true if verified 
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 * @throws NoSuchAlgorithmException 
	 */
	public static boolean verify(X509Certificate certificate, String algorithmUri, byte[] data, byte[] signature) 
	throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
		if (algorithmUri==null) return true;
        if (certificate==null || data==null || signature==null)
        	throw new IllegalArgumentException("null arg");

		Signature signer = CryptoUtil.getAsymmetricSignature(algorithmUri);		
		signer.initVerify( certificate );
		signer.update( data );
		return signer.verify(signature);
	}	
	
	/** 
	 * Load X.509 Certificate from an url
	 * 
	 * @param url
	 * @return Certificate
	 * @throws IOException 
	 */
	public static X509Certificate readX509Certificate(URL url) 
	throws IOException
	{
		URLConnection connection = url.openConnection();
		InputStream is = connection.getInputStream();
		try { 
			CertificateFactory servercf = CertificateFactory.getInstance("X.509");
			return (X509Certificate) servercf.generateCertificate(is);
		} catch (CertificateException e) {
			// We can assume certificates are valid is most cases
			throw new RuntimeException(e);
		} finally {
			is.close();
		}
	}	
	
	/** 
	 * Load X.509 Certificate from a file
	 * 
	 * @param file
	 * @return Certificate
	 * @throws IOException 
	 */
	public static X509Certificate readX509Certificate(File file) 
	throws IOException
	{
		return readX509Certificate(file.toURI().toURL());
	}	
	
	/**
	 * Write certificate to a file
	 * @param cert
	 * @param file
	 * @throws IOException
	 */
	public static void writeCertificate(java.security.cert.Certificate cert, File file)
	throws IOException
	{
		FileUtil.writeFile(file, encodeCertificate(cert));
	}
	
	/**
	 * Create SHA-1 Thumbprint
	 * @param data
	 * @return thumbprint
	 */
	public static byte[] createThumbprint(byte[] data)
	{		
		try {
			MessageDigest shadigest = MessageDigest.getInstance("SHA1");
			return shadigest.digest( data );				
		} catch (NoSuchAlgorithmException e) {
			throw new Error(e);
		}
	}
	
	public static byte[] encodePrivateKey(PrivateKey privKey)
	{
		return privKey.getEncoded();
	}
	
	public static RSAPrivateKey decodeRSAPrivateKey(byte[] encodedPrivateKey) 
	{
		try {
			RSAKeyParameters par = (RSAKeyParameters) PrivateKeyFactory.createKey(encodedPrivateKey);
			RSAPrivateKeySpec spec = new RSAPrivateKeySpec(par.getModulus(), par.getExponent());
			KeyFactory factory = KeyFactory.getInstance("RSA");
			return (RSAPrivateKey) factory.generatePrivate(spec);
		} catch (NoSuchAlgorithmException e) {
			throw new Error(e);
		} catch (IOException e1) {
			// Unexpected
			throw new RuntimeException(e1);
		} catch (InvalidKeySpecException e2) {
			throw new RuntimeException(e2);
		}
	}
	
	public static byte[] encodeCertificate(java.security.cert.Certificate cert)
	{
		try {
			return cert.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Decode X509 Certificate
	 * @param encodedCertificate
	 * @return X509 certificate
	 * @throws CertificateException
	 */
	public static X509Certificate decodeX509Certificate(byte[] encodedCertificate)
	throws CertificateException
	{
		try {
			if (encodedCertificate==null) throw new IllegalArgumentException("null arg");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			ByteArrayInputStream bais = new ByteArrayInputStream( encodedCertificate );
			X509Certificate result = (X509Certificate) cf.generateCertificate( bais );
			bais.close();
			return result;		
		} catch (IOException e) {
			// ByteArrayInputStream will not throw this
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Load private key from a key store
	 * 
	 * @param keystoreUrl url to key store
	 * @param password password to key store
	 * @return private key
	 * @throws IOException
	 */
	public static RSAPrivateKey loadFromKeyStore(URL keystoreUrl, String password) throws IOException
	{
		// Open pfx-certificate
		URLConnection connection = keystoreUrl.openConnection();
		InputStream is = connection.getInputStream();
		try {
			// Open key store and load the key
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(is, null);
			Enumeration<String> aliases = keyStore.aliases();

			Key key = null;
			while (aliases.hasMoreElements()) {
				String a = (String) aliases.nextElement();
				key = keyStore.getKey(a, password.toCharArray());
			}

			return (RSAPrivateKey) key;
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		} finally {
			is.close();
		}
	}	
	
	public static boolean saveKeyPairToProtectedStore(
			org.opcfoundation.ua.transport.security.KeyPair keyPairToSave,
			String storeLocation, String alias, String storePW, String privatePW)
			throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException {
		KeyStore store = null;

		// initialize and open keystore
		store = KeyStore.getInstance("JKS");
		File keystoreFile = new File(storeLocation);
		FileInputStream in = new FileInputStream(keystoreFile);
		store.load(in, storePW.toCharArray());
		in.close();

		// create certificate chain containing only 1 certificate
		Certificate[] chain = new Certificate[1];
		chain[0] = keyPairToSave.certificate.getCertificate();
		store.setKeyEntry(alias, keyPairToSave.privateKey.getPrivateKey(),
				privatePW.toCharArray(), chain);

		FileOutputStream fOut = new FileOutputStream(storeLocation);

		store.store(fOut, storePW.toCharArray());

		return true;
	}
	
	public static org.opcfoundation.ua.transport.security.KeyPair loadKeyPairFromProtectedStore(
			String storeLocation, String alias, String storePW, String privatePW)
			throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, UnrecoverableKeyException {

		KeyStore store = null;

		// initialize and open keystore
		store = KeyStore.getInstance("JKS");
		File keystoreFile = new File(storeLocation);
		FileInputStream in = new FileInputStream(keystoreFile);
		store.load(in, storePW.toCharArray());
		in.close();

		// try to load certificate from store
		X509Certificate cert = (X509Certificate) store.getCertificate(alias);

		// Try to load private key from keystore
		RSAPrivateKey key = (RSAPrivateKey) store.getKey(alias, privatePW
				.toCharArray());

		return new org.opcfoundation.ua.transport.security.KeyPair(new Cert(
				cert), new PrivKey(key));
	}
	




	
	
	private static Provider PROV = new BouncyCastleProvider();
	//private static String HASH_ALG = "MD5";
	private static String KEY_ALG = "RSA";
	private static String STORE_TYPE = "JKS";
	//private static String STORE_PASSWD = "123456";
	//private static String KEY_PASSWD = "123456";
	private static String ALIAS = "CLIENT";
	private static int KEY_SIZE = 1024;
	/**
	 * 
	 * @param commonName - Common Name (CN) for generated certificate
	 * @param organisation - Organisation (O) for generated certificate
	 * @param applicationUri - Alternative name (one of x509 extensiontype) for generated certificate. Must not be null
	 * @param validityTime - the time that the certificate is valid (in days)
	 * @return
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateEncodingException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 * @throws NoSuchProviderException
	 * @throws SignatureException
	 * @throws CertificateParsingException
	 */
	public static org.opcfoundation.ua.transport.security.KeyPair createApplicationInstanceCertificate(
			String commonName, String organisation, String applicationUri,
			int validityTime) throws IOException, InvalidKeySpecException,
			NoSuchAlgorithmException, CertificateEncodingException,
			InvalidKeyException, IllegalStateException,
			NoSuchProviderException, SignatureException,
			CertificateParsingException {
		if (applicationUri == null)
			throw new NullPointerException("applicationUri must not be null");
		//Add provider for generator
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		//Initializes generator 
		SecureRandom srForCert = new SecureRandom();
		RSAKeyPairGenerator genForCert = new RSAKeyPairGenerator();
	
		//Used for generating prime
		Random r = new Random(System.currentTimeMillis());
		int random = -1;
		
		while(random < 3){
			random = r.nextInt(32);
		}
		//calculate(generate) possible value for public modulus
		//used method is "monte carlo -algorithm", so we calculate it as long as it generates value.
		BigInteger value = null;
		while(value == null){
			value = BigInteger.probablePrime(random, new SecureRandom());
		}
		
		//Generate (Java) keypair
		genForCert.init(new RSAKeyGenerationParameters(value, srForCert, KEY_SIZE,80));
		AsymmetricCipherKeyPair keypairForCert = genForCert.generateKeyPair();
		
		//Extract the keys from parameters
		logger.debug("Generated keypair, extracting components and creating public structure for certificate");
		RSAKeyParameters clientPublicKey = (RSAKeyParameters) keypairForCert.getPublic();
        RSAPrivateCrtKeyParameters clientPrivateKey = (RSAPrivateCrtKeyParameters) keypairForCert.getPrivate();
        // used to get proper encoding for the certificate
        RSAPublicKeyStructure clientPkStruct = new RSAPublicKeyStructure(clientPublicKey.getModulus(), clientPublicKey.getExponent());
        logger.debug("New public key is '" + makeHexString(clientPkStruct.getEncoded()) + 
				", exponent=" + clientPublicKey.getExponent() + ", modulus=" + clientPublicKey.getModulus());
       
        
        // JCE format needed for the certificate - because getEncoded() is necessary...
        PublicKey certPubKey = KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(clientPublicKey.getModulus(), clientPublicKey.getExponent()));
        // and this one for the KeyStore
        PrivateKey certPrivKey = KeyFactory.getInstance("RSA").generatePrivate(
                new RSAPrivateCrtKeySpec(clientPublicKey.getModulus(), clientPublicKey.getExponent(),
                		clientPrivateKey.getExponent(), clientPrivateKey.getP(), clientPrivateKey.getQ(), 
                		clientPrivateKey.getDP(), clientPrivateKey.getDQ(), clientPrivateKey.getQInv()));
        
        
        //The data for the certificate..
        Calendar expiryTime = Calendar.getInstance();
        expiryTime.add(Calendar.DAY_OF_YEAR, validityTime);
        
        X509Name certificateX509Name = new X509Name(
        		"CN="+commonName+", O="+organisation+", C="+System.getProperty("user.country"));
       	
       	X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
       	BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
       	certGen.setSerialNumber(serial);
       	//Issuer and subject must be the same (because this is self signed)
       	certGen.setIssuerDN(certificateX509Name);
       	certGen.setSubjectDN(certificateX509Name);
       	
       	//expiry & start time for this certificate
       	certGen.setNotBefore(new Date(System.currentTimeMillis() - 1000*60*60)); //take 60 minutes (1000 ms * 60 s * 60) away from system clock (in case there is some lag in system clocks)
        certGen.setNotAfter(expiryTime.getTime());
        
        certGen.setPublicKey(certPubKey);
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

		
		//******* X.509 V3 Extensions *****************
		
		SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(
						new ByteArrayInputStream(certPubKey.getEncoded()))
						.readObject());
		SubjectKeyIdentifier ski = new SubjectKeyIdentifier(apki);
		
		/*certGen.addExtension(X509Extensions.SubjectKeyIdentifier, true,
				new DEROctetString(ski//new SubjectKeyIdentifier Structure(apki/*certPubKey)));
	       */
		certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, ski);
		certGen.addExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(false));
		certGen.addExtension(X509Extensions.KeyUsage, true,  /*new DEROctetString(new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.nonRepudiation | KeyUsage.dataEncipherment | KeyUsage.keyCertSign ))*/new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.nonRepudiation | KeyUsage.dataEncipherment | KeyUsage.keyCertSign ));
	        
		 BasicConstraints b = new BasicConstraints(false);
	        
		Vector<KeyPurposeId> extendedKeyUsages = new Vector<KeyPurposeId>();
		extendedKeyUsages.add(KeyPurposeId.id_kp_serverAuth);
		extendedKeyUsages.add( KeyPurposeId.id_kp_clientAuth);
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, /*new DEROctetString(new ExtendedKeyUsage(extendedKeyUsages))*/new ExtendedKeyUsage(extendedKeyUsages));
		
		
		// create the extension value
		ASN1EncodableVector names = new ASN1EncodableVector();
		names.add(new GeneralName(GeneralName.uniformResourceIdentifier,
				applicationUri));
//		GeneralName dnsName = new GeneralName(GeneralName.dNSName, applicationUri);
//		names.add(dnsName);
		final GeneralNames subjectAltNames = new GeneralNames(new DERSequence(names));
		
		certGen.addExtension(X509Extensions.SubjectAlternativeName, true, subjectAltNames);
	   
		// AuthorityKeyIdentifier

		final GeneralNames certificateIssuer = new GeneralNames(new GeneralName(certificateX509Name));
		AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki,certificateIssuer,serial);
		
		
		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,aki);
		//***** generate certificate ***********/
		X509Certificate cert = certGen.generate(certPrivKey, "BC");
		
	
		
		//Encapsulate Certificate and private key to CertificateKeyPair
		Cert certificate = new Cert(cert);
		org.opcfoundation.ua.transport.security.PrivKey UAkey = new org.opcfoundation.ua.transport.security.PrivKey((RSAPrivateKey) certPrivKey);
		return new org.opcfoundation.ua.transport.security.KeyPair(certificate, UAkey);
	}
	@Deprecated //Use createApplicationInstanceCertificate instead of this...all the x.509 cert fields are not fulfilled in this
	public static org.opcfoundation.ua.transport.security.KeyPair generateKeyPair(String CN) throws Exception
	{
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(KEY_ALG, PROV);
		keyGenerator.initialize(KEY_SIZE);
		KeyPair key = keyGenerator.generateKeyPair();
		PublicKey publicKey = key.getPublic();
		PrivateKey privateKey = key.getPrivate();
		
		//Keystore not needed in this function (at the moment)
		///KeyStore keyStore = null;

		////keyStore = KeyStore.getInstance(STORE_TYPE);
		///keyStore.load(null,STORE_PASSWD.toCharArray());

		//Use BouncyCastle as Security provider
		new CryptoUtil();
		//////X509Certificate[] chain = new X509Certificate[1];

		//Generates new certificate..add the information needed for the generator
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal subjectName = new X500Principal("CN="+CN);
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		//X509Certificate caCert=null;
		certGen.setIssuerDN(subjectName);
		Date notBefore = new Date();
		Date notAfter = new Date();
		notBefore.setTime( notBefore.getTime() - 1000*60*60 );
		notAfter.setTime( notAfter.getTime() + 1000*60*60*24*365 );
		certGen.setNotBefore( notBefore );
		certGen.setNotAfter( notAfter );
		certGen.setSubjectDN(subjectName);
		certGen.setPublicKey(publicKey);
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		
		//X.509 V3 Extensions...these are just examples
		
		//certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,new AuthorityKeyIdentifierStructure(caCert));
		///7certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
		////		new SubjectKeyIdentifierStructure(key.getPublic()));
	       
		certGen.addExtension(X509Extensions.SubjectKeyIdentifier, true,
				new DEROctetString(new SubjectKeyIdentifierStructure(key.getPublic())));
	  
		
	        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
	       
	        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyCertSign ));
	        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
		
		
		/////chain[0]= certGen.generate(privateKey, "BC"); // note: private key of CA
	        //Generate
	        X509Certificate caCert = certGen.generate(privateKey, "BC");
		
		//Encapsulate Certificate and private key to CertificateKeyPair
		Cert cert = new Cert(caCert);
		org.opcfoundation.ua.transport.security.PrivKey UAkey = new org.opcfoundation.ua.transport.security.PrivKey((RSAPrivateKey) privateKey);
		return new org.opcfoundation.ua.transport.security.KeyPair(cert, UAkey);
		/*keyStore.setEntry(ALIAS,new KeyStore.PrivateKeyEntry(privateKey, chain),
				new KeyStore.PasswordProtection(KEY_PASSWD.toCharArray())
		);

		// Write out the keystore
		FileOutputStream keyStoreOutputStream = new FileOutputStream(keystorePath);
		keyStore.store(keyStoreOutputStream, "123456".toCharArray());
		keyStoreOutputStream.close();*/

	}
  
	
	
	 
	 /** Hex chars for makeHexString-method **/
	 private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
	 
	 /**
	  * Convience method for calculating "hex-string" from given byte[].
	  * 
	  */
		public static String makeHexString( byte[] bytes ) {
			StringBuffer sb = new StringBuffer();
			
			int i=0;
			while ( i < bytes.length ) {
				sb.append( HEX_CHARS[ (bytes[i] >> 4) & 0x0F ] );
				sb.append( HEX_CHARS[ bytes[i] & 0x0F] );
				i++;
			}
			return sb.toString();
		}
	/** 
	 * check that X.509 Certificate exists in an url
	 * 
	 * @param url
	 * @return Certificate
	 * @throws IOException 
	 * @throws IOException 
	 * @throws IOException 
	 */
	public static boolean FindCertificateFromFile(URL url) throws IOException {

			URLConnection connection = null;
			InputStream is = null;
			try {
				connection = url.openConnection();
				is = connection.getInputStream();
			} catch (IOException e) {
				
				return false;
			}
			catch (NullPointerException e) {
				return false;
			}
			is.close();
			return true;
			
			
			
			
			
	}
	/**
	 * generates new certificate chain and returns it..
	 * first certificate in the returned chain is the issued certificate and the second one is CA certificate
	 * 
	 * @return certificates 
	 * @throws Exception
	 */
    public static X509Certificate[] createCertificateChain()throws Exception {
  

    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
         // create the keys
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(1024, new SecureRandom());
        KeyPair             pair = keyGen.generateKeyPair();

        X509Certificate  rootCert = generateRootCertificate(pair);
 	  
        //Create certificate request
        PKCS10CertificationRequest request = createCertificateRequest();

        // validate the certification request
        if (!request.verify("BC"))  {
            System.out.println("request failed to verify!");
            System.exit(1);
        }
        
        // create the certificate using the information in the request
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(rootCert.getSubjectX500Principal());
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(request.getCertificationRequestInfo().getSubject());
        certGen.setPublicKey(request.getPublicKey("BC"));
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(rootCert));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(request.getPublicKey("BC")));
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        
        X509Certificate  issuedCert = certGen.generate(pair.getPrivate());
        X509Certificate[] chain={issuedCert, rootCert };
          
        //Write certificates to file so we are able to retrieve the also te private key
       /* URL certURL = CertificateUtils.class.getResource( "createdCerts.pem" );
        
        URLConnection connection = certURL.openConnection();
		InputStream is = connection.getInputStream();
        CertificateFactory servercf = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) servercf.generateCertificate(is);
		
		PEMWriter        testWriter = new PEMWriter(new OutputStreamWriter(System.out));
		testWriter.writeObject(cert);*/
		return chain;
    }
    
    public static void writeCertificatesToPemFile(String[] pemFilePaths, X509Certificate[] certificates) throws IOException{
    	//Write certificates
        //PEMWriter        pemWrt = new PEMWriter(new OutputStreamWriter(System.out));
    	for(int index = 0; index < certificates.length; index++){
    		File savePath = new File(pemFilePaths[index]);
    		System.out.println ("File path to save : " + savePath.getCanonicalPath());
    		PEMWriter        pemWrt = new PEMWriter(new OutputStreamWriter(new FileOutputStream(savePath.getCanonicalPath()) ));
    		
            pemWrt.writeObject(certificates[index]);
            pemWrt.close();
    	}
      
      
       
        
    }
    
    /**
     * Function returns new CertificateRequest using SHA1RSA algorithm..
     * Common Name, and Country are set automatically
     * 
     * @return certification request
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
     public static PKCS10CertificationRequest createCertificateRequest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException{
     	  // create the keys
         KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
         kpGen.initialize(1024, new SecureRandom());
         KeyPair          pair = kpGen.generateKeyPair();
         
  	  //Create PKCS10 Request
 	  X500Principal subject= new X500Principal("CN=UA CA Test Certificate ,C=FI");
         PKCS10CertificationRequest  request = new PKCS10CertificationRequest("SHA1withRSA",subject,pair.getPublic(),null,pair.getPrivate());
 	 return request;

     }
     public static void createCertificateRequest(String issuer, String pathToWrite) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException{
   	 
 	  //Create PKCS10 Request
       PKCS10CertificationRequest  request = createCertificateRequest();
 	 //Write it 
 	  FileOutputStream reqFile= new FileOutputStream(pathToWrite+"/request.pem");
       PEMWriter        pemWrt = new PEMWriter(new OutputStreamWriter(reqFile));
       pemWrt.writeObject(request);
       pemWrt.close();

   }
    
    
    private static X509Certificate generateRootCertificate(KeyPair pair) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException{
    	// generate root certificate
        X509V3CertificateGenerator  certGenRoot = new X509V3CertificateGenerator();
        certGenRoot.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGenRoot.setIssuerDN(new X500Principal("CN=Test Certificate"));
        certGenRoot.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGenRoot.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGenRoot.setSubjectDN(new X500Principal("CN=Test Certificate"));
        certGenRoot.setPublicKey(pair.getPublic());
        certGenRoot.setSignatureAlgorithm("SHA1WithRSAEncryption");
        return certGenRoot.generate(pair.getPrivate(), "BC");
    }
    
    private static PKCS10CertificationRequest readRequestFromFile(String filename) throws IOException{
    	// Read the certification request
        FileInputStream reqFile= new FileInputStream(filename);
        PEMReader        pemRead = new PEMReader(new InputStreamReader(reqFile));
        PKCS10CertificationRequest request=(PKCS10CertificationRequest) pemRead.readObject();
        pemRead.close();
        return request;
    }

	/**
	 * Gets the signing key from the key store and signs the data.
	 * 
	 * @param certificate
	 * @param signingAlgorithm
	 * @param nonce
	 * @return signed data
	 * @throws KeyStoreException 
	 * @throws NoSuchAlgorithmException 
	 * @throws UnrecoverableKeyException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public static byte[] signData(
			X509Certificate certificate, 
			String signingAlgorithm, 
			byte[] nonce,
			KeyStore store)
	throws ServiceResultException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{

		Signature signature = null;
		byte[] realSignature = null;

			// Get the alias name for the specified key entry that created the certificate.
			String alias = store.getCertificateAlias(certificate);

			if (alias == null) 
				throw new ServiceResultException(
						StatusCodes.Bad_CertificateInvalid,
						"Certificate with subject = " + certificate.getSubjectX500Principal().getName() + 
						" does not contain an RSA private key.");

			// If the certificate was created from the key entry the key entry's alias is returned.
			// If the certificate was simply added as a trusted certificate, the certificate's  alias is returned
			Key key = store.getKey(alias, "opcuajava".toCharArray());
			if (!(key instanceof PrivateKey)) {
				throw new ServiceResultException(
						StatusCodes.Bad_CertificateInvalid,
						"Certificate with subject = " + certificate.getSubjectX500Principal().getName() + 
						" does not contain an RSA private key.");
			}

			// Create a Signature object and initialize it with the private key
			signature = Signature.getInstance("SHA1withRSA");
			signature.initSign((PrivateKey)key);

			// Update and sign the data
			ByteArrayInputStream bis = new ByteArrayInputStream(nonce);
			int bufferSize = 1024;
			byte[] buffer = new byte[bufferSize];
			int n = bis.read(buffer, 0, bufferSize);
			int count = 0;
			while (n != -1) {
				count += n;
				signature.update(buffer, 0, n);
				n = bis.read(buffer, 0, bufferSize);
			}

			realSignature = signature.sign();

		return realSignature;
	}

	static {
	}
   
}
