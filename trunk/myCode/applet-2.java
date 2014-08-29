package com.morpho;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.MultiSelectable;
import javacard.framework.Shareable;
import javacard.framework.Util;

import org.globalplatform.GPSystem;
import org.globalplatform.GlobalService;
import org.globalplatform.HTTPAdministration;
import org.globalplatform.HTTPReportListener;

public class TriggerSession implements HTTPReportListener

{

	private static short reportListenerState;
	
	public void httpAdministationSessionReport(short status)
	{
		reportListenerState = status;
	}
	   
    public void triggerSession(byte[] data, short dataOffset, short dataLength )
    {
		final short FAMILY_HTTP_ADMINISTRATION = (short) (GPSystem.FAMILY_HTTP_ADMINISTRATION << 8);
		
		// get GlobalService object
		GlobalService globalService = GPSystem.getService(null, FAMILY_HTTP_ADMINISTRATION);
		
		// getServiceInterface
		HTTPAdministration httpAdmin = (HTTPAdministration) globalService.getServiceInterface(GPSystem.getRegistryEntry(null), FAMILY_HTTP_ADMINISTRATION, null, (short) 0, (short) 0);

		// trigger HTTP Administration to start Session
		httpAdmin.requestHTTPAdministrationSession(data, dataOffset, dataLength);
    }	
}
