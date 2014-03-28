package core;

public class SignedSoftwareCertificate {
	
	protected byte[] Certificate;
	protected byte[] Signature;
	
	public void setSoftwareCertificate(byte[] Certificate, byte[] Signature)
	{
		this.Certificate = Certificate;
		this.Signature = Signature;
	}
	
	public byte[] getCertificate()
	{
		return this.Certificate;
	}
	public byte[] getSignature()
	{
		return this.Signature;
	}
	
}
