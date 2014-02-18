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
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.util.Arrays;

import junit.framework.TestCase;

import org.opcfoundation.ua.builtintypes.XmlElement;
import org.w3c.dom.Node;

import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;

public class TestXmlElement extends TestCase {

	private static final Charset UTF8 = Charset.forName("utf-8");

	// Files 1 and 2 are string-to-string different but has the same content
	// File 3 differs from 1 and 2

	String file1 = "SampleXmlData1.xml";
	String file2 = "SampleXmlData2.xml";
	String file3 = "SampleXmlData3.xml";

	String doc1, doc2, doc3;
	byte[] enc1, enc2, enc3;
	XmlElement xeDoc1, xeDoc2, xeDoc3, xeEnc1, xeEnc2, xeEnc3;

	protected void setUp() throws Exception {
		doc1 = loadDoc(file1);
		doc2 = loadDoc(file2);
		doc3 = loadDoc(file3);

		enc1 = loadBytes(file1);
		enc2 = loadBytes(file2);
		enc3 = loadBytes(file3);

		xeDoc1 = new XmlElement(doc1);
		xeDoc2 = new XmlElement(doc2);
		xeDoc3 = new XmlElement(doc3);

		xeEnc1 = new XmlElement(enc1);
		xeEnc2 = new XmlElement(enc2);
		xeEnc3 = new XmlElement(enc3);
	}

	public void testHashCode() {
		assertEquals(xeDoc1.hashCode(), xeDoc2.hashCode());
		assertEquals(xeDoc1.hashCode(), xeEnc1.hashCode());
		assertEquals(xeDoc1.hashCode(), xeEnc2.hashCode());
		assertNotSame(xeDoc1.hashCode(), xeEnc1.hashCode());
		assertNotSame(xeDoc1.hashCode(), xeDoc2.hashCode());
		assertNotSame(xeDoc2.hashCode(), xeEnc3.hashCode());
	}

	public void testEqualsObject() {
		assertEquals(xeDoc1, xeDoc2);
		assertEquals(xeDoc1, xeEnc1);
		assertEquals(xeDoc2, xeEnc1);
		assertEquals(xeDoc2, xeEnc2);
		assertEquals(xeDoc3, xeEnc3);
		assertNotSame(xeDoc1, xeDoc3);
		assertNotSame(xeDoc2, xeDoc3);
		assertNotSame(xeEnc1, xeEnc3);
		assertNotSame(xeEnc2, xeEnc3);
		assertNotSame(xeEnc1, xeDoc3);
	}

	public void testgetDataDocument() {
		assertTrue(Arrays.equals(xeDoc1.getData(), xeEnc1.getData()));
		assertTrue(Arrays.equals(xeDoc2.getData(), xeEnc2.getData()));
		assertTrue(Arrays.equals(xeDoc3.getData(), xeEnc3.getData()));
	}

	public void testgetValue() {
		assertEquals(xeDoc1.getValue(), xeEnc1.getValue());
		assertEquals(xeDoc2.getValue(), xeEnc2.getValue());
		assertEquals(xeDoc3.getValue(), xeEnc3.getValue());
	}

	public void testGetNode() {
		Node n1 = xeDoc1.getNode();
		Node n2 = xeDoc1.getNode();
		Node n3 = xeDoc1.getNode();
		Node m1 = xeEnc1.getNode();
		Node m2 = xeEnc1.getNode();
		Node m3 = xeEnc1.getNode();
		// assertTrue( n1.equals(n2) );
		// assertFalse( n1.equals(n3) );
		// assertTrue( n1.equals(m1) );
		// assertTrue( n1.equals(m2) );
		// assertFalse( n1.equals(n3) );
		// assertFalse( n1.equals(m3) );
	}

	public void testToString() {
		System.out.println(xeEnc1.toString());
		System.out.println(xeEnc2.toString());
		System.out.println(xeEnc3.toString());
	}

	static String loadDoc(String file) {
		return loadDoc(TestXmlElement.class.getResource(file));
	}

	static String loadDoc(URL url) {
		try {
			URLConnection connection = url.openConnection();
			InputStream is = connection.getInputStream();
			try {
				byte[] doc = readResource(is);
				return new String(doc, UTF8);
			} finally {
				is.close();
			}
		} catch (IOException e) {
			throw new RuntimeException();
		}
	}

	static byte[] loadBytes(String file) {
		return loadBytes(TestXmlElement.class.getResource(file));
	}

	static byte[] loadBytes(URL url) {
		try {
			URLConnection connection = url.openConnection();
			InputStream is = connection.getInputStream();
			try {
				return readResource(is);
			} finally {
				is.close();
			}
		} catch (IOException e) {
			throw new RuntimeException();
		}
	}

	/**
	 * Reads entire resource from an input stream
	 * 
	 * @param is
	 * @return resource
	 * @throws IOException
	 */
	public static byte[] readResource(InputStream is) throws IOException {
		byte[] buf = new byte[4096];
		ByteOutputStream os = new ByteOutputStream();

		for (;;) {
			int bytesRead = is.read(buf);
			if (bytesRead == -1)
				break;
			os.write(buf, 0, bytesRead);
		}

		return os.toByteArray();

	}
}