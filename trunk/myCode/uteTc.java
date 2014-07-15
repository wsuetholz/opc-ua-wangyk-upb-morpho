/* Copyright  (c)  2003-2014  Morpho e-Documents Division (Morpho Cards GmbH).  This software is the
 * confidential and proprietary information of Morpho e-Documents Division (Morpho Cards GmbH).
 * All rights reserved.
 *
 * Morpho e-Documents Division (Morpho Cards GmbH)
 * makes no representations or warranties  about  the 
 * suitability of the software, either express or implied, including but
 * not limited to the implied warranties of merchantability, fitness for
 * a  particular purpose, or non-infringement. 
 * Morpho e-Documents Division (Morpho Cards GmbH) shall not
 * be  liable for any damages suffered by licensee as a result of using,
 * modifying or distributing this software or its derivatives.
 * This copyright notice must appear in all copies of this software.
 ***********************************************************************
 *
 * $File: //Technology/cardManagement/R7.3.21/tst/src/cardManagement/AmendmentB/ComponentTest/AdminAgent/BipProtocol/Open_ChannelValid.java $
 *
 * Last submit:
 * $Revision: #3 $
 * $Change: 501506 $
 * $DateTime: 2014/04/24 11:11:07 $
 * $Author: kamran.khan $
 **********************************************************************/

package cardManagement.AmendmentB.ComponentTest.AdminAgent.BipProtocol;

import java.util.Hashtable;

import com.orga.cardManagement.CardManagementTestApplets;
import com.orga.cardManagement.cmdSequences.ResetCommands;
import com.orga.sat.ota.OtaDownload;
import com.orga.selector.Selector;
import com.orga.ute.cardmanagment.loadfile.ILoadFile;
import com.orga.ute.commands.op201.cmobjects.AppletManager;
import com.orga.ute.commands.op201.cmobjects.IssuerSecurityDomain;
import com.orga.ute.commands.op201.cmobjects.OffCardManager;
import com.orga.ute.control.logging.Log;
import com.orga.ute.control.testframe.Command;
import com.orga.ute.control.testframe.TestcaseInfo;
import com.orga.ute.control.testframe.UTEScenario;
import com.orga.ute.ramoverhttp.AdminAgentTools;
import com.orga.ute.ramoverhttp.HttpConstants;
import com.orga.ute.ramoverhttp.http.ContentField;
import com.orga.ute.ramoverhttp.http.HeaderField;
import com.orga.ute.ramoverhttp.http.HttpRequest;
import com.orga.ute.ramoverhttp.http.HttpResponse;
import com.orga.ute.ramoverhttp.http.StatusCode;
import com.orga.ute.ramoverhttp.tls.Ciphersuite;
import com.orga.ute.ramoverhttp.transport.HttpConnection;
import com.orga.ute.ramoverhttp.transport.IScwsConnectionOpener;
import com.orga.ute.ramoverhttp.transport.bip.BipConnection;
import com.orga.ute.ramoverhttp.transport.bip.admin.BipAdminConnectionOpener;
import com.orga.ute.ramoverhttp.transport.bip.admin.TriggerApplet095;
import com.orga.ute.ramoverhttp.transport.bip.admin.TriggerPushSMS;
import com.orga.ute.ramoverhttp.transport.bip.admin.tlv.AdminAgentConfigurationParameters;
import com.orga.ute.ramoverhttp.transport.bip.admin.tlv.ConnectionParameters;
import com.orga.ute.ramoverhttp.transport.bip.admin.tlv.HttpPostParameters;
import com.orga.ute.ramoverhttp.transport.bip.admin.tlv.SecurityParameters;
import com.orga.ute.ramoverhttp.transport.tls.ClientTls;
import com.orga.ute.service.util.Blob;
import com.orga.ute.toolkit.sms.ConversionUtil;

public class Open_ChannelValid extends UTEScenario {
	// non_generated_code_start
	// non_generated_code_end

	protected static Hashtable<String, TestcaseInfo> testcaseInfos = new Hashtable<String, TestcaseInfo>();

	public static TestcaseInfo getTestcaseInfo(String testcaseName) {
		return testcaseInfos.get(testcaseName);
	}

	// [testcase_info_start: 9110]
	/**
	 * 
	 * TESTCASE 001
	 * 
	 * <p>
	 * Target: send buffer size in Triggering SMS less then 1500 bytes
	 * 
	 * <p>
	 * Testcase Description: Test to verify that send buffer size in Triggering
	 * SMS (Conection Parameter) less then 1500 bytes .
	 * 
	 * Step 1: Send Push SMS with 1499 bytes buffer size in Connection Parameter
	 * . Step 2 : Recieve open channel with Buffer Size 1499 bytes
	 * 
	 * <p>
	 * Expected Response Data:
	 * 
	 * 
	 * <p>
	 * Expected Statusword:
	 * 
	 * 
	 * <p>
	 * Expected Result Description: Connection should be establish and session
	 * must be start.
	 * 
	 * @throws Exception
	 *             transfers not catched exceptions
	 */
	static {
		// testcaseID = 9110
		TestcaseInfo info = new TestcaseInfo();
		info.setInfo(TestcaseInfo.TITLE, "send buffer size in Triggering SMS less then 1500 bytes");
		info.setTestcaseNo(1);
		info.setInfo(TestcaseInfo.DESCRIPTION, "Open_ChannelValid: send buffer size in Triggering SMS less then 1500 bytes");
		info.setInfo(TestcaseInfo.STATUS, "implemented");
		info.setInfo(TestcaseInfo.STATUS_DESCRIPTION, "(cb,09.01.13) 8634 added as recommended TB id");
		info.setInfo(TestcaseInfo.ID, "9110");
		info.setInfo(Selector.SELECTIONRULE, "GlobalPlatform221AmendmentB_Supported");
		testcaseInfos.put("tc_001", info);
	}

	// [testcase_info_end: 9110]

	// [testcase_start: 9110]
	public void tc_001() throws Exception {
		testcaseBegin(testcaseInfos.get("tc_001"));
		// ************************* PREPARATION *************************
		Log.writePreBlock();

		AdminAgentTools adminAgentTools;
		String bearerDescription;
		int bufferSizeAdmin;
		String networkAccessName;
		String loginName;
		String loginPasswort;
		String tcpPort;
		String dataDestinationAddressIPv4;
		OtaDownload otaPush;
		String counter;
		ConnectionParameters connectionParameter;

		adminAgentTools = new AdminAgentTools();
		otaPush = new OtaDownload(100);

		counter = "0000000003";

		otaPush.setSingleSMSLength(120);
		otaPush.getCp().getToolkitApplicationReference().set("380011");
		otaPush.getCp().getSecurityParameterIndicator().set("1201"); // use PoR
		otaPush.getCp().getCipherKeyIdentifier().set("15");
		otaPush.getCp().getSignatureKeyIdentifier().set("15");
		otaPush.getCp().setKID("31676D425BB0F271CD163CBAB28D84A3");
		otaPush.setCounter(counter);

		// Type=GPRS, Parameter=010101010102
		bearerDescription = "02010101010102";
		// Set Buffer Size
		bufferSizeAdmin = 1500;
		// Network access name
		networkAccessName = "morpho.com";
		loginName = "admin";
		loginPasswort = "root";
		// Interface transport level: protocol=TCP, UICC in client mode,
		// port=9096
		tcpPort = "9096";
		dataDestinationAddressIPv4 = "80.66.10.152";

		connectionParameter = new ConnectionParameters(bearerDescription, bufferSizeAdmin, networkAccessName, loginName, loginPasswort, tcpPort,
				dataDestinationAddressIPv4);

		SecurityParameters securtiyParameters = new SecurityParameters();
		securtiyParameters.setValue("143839333930313030303030313239353036393033024001");

		HttpPostParameters getHttpPostParameters = new HttpPostParameters();
		getHttpPostParameters.setValue("8A1138302E36362E31302E3230303A383038308B033030378C0B2F4345482F6365686F6370");

		TriggerPushSMS trigger = new TriggerPushSMS(otaPush, connectionParameter, securtiyParameters, getHttpPostParameters);

		// Set Retry Policy
		// Retry Policy Parameters:
		// Retry counter: 0002
		// Timer value: 00:00:03
		trigger.setRetryPolicyParameters(adminAgentTools.getDefaultConnectionOpener().getAdminTrigger().getRetryPolicyParameters());

		BipAdminConnectionOpener bipOpener = new BipAdminConnectionOpener(bufferSizeAdmin, trigger);

		// ***************************** TEST ****************************
		Log.writeExecuteBlock();

		// HTTP over BIP on channel 3
		HttpConnection httpConnection = new HttpConnection(new BipConnection(3, bipOpener));

		// add TLS security to HTTP
		ClientTls clientTls = new ClientTls(securtiyParameters, "0DB76915A80ED3F5272DA0809EFDB7E94F3B4068E9D02C1D", Ciphersuite.TLS_PSK_WITH_NULL_SHA256);

		httpConnection.setTlsLayer(clientTls);

		// Send HTTP POST request
		httpConnection.receiveHttpRequest(this);
		

		Blob cmd;
		HttpResponse hr;
		String aidInstanceRfm = "D27600002841070101020002B0002601";

		cmd = new Blob();

		hr = new HttpResponse();
		hr.setStatusCode(StatusCode.SC_200_OK);
		hr.setHeaderField(HeaderField.X_ADMIN_PROTOCOL, HttpConstants.ADMIN_PROTOCOL);
		// hr.setHeaderField(HeaderField.X_ADMIN_NEXT_URI , "/CEH/cehocp");
		hr.setHeaderField(HeaderField.CONTENT_TYPE, HttpConstants.ADMIN_CONTENT_TYPE);
		hr.setHeaderField(HeaderField.TARGET_APPLICATION, hr.targAppAid(aidInstanceRfm)); // D27600002841070101020002B0002601
																							// //
		cmd.addBlob(ConversionUtil.byteArray("A0A40000022FE2A0B0000006"));
		hr.setContentField(new ContentField(cmd));

		httpConnection.send(hr, this);
		
	
		aidInstanceRfm = "D27600002841070101020005B0002301";

		cmd = new Blob();

		hr = new HttpResponse();
		hr.setStatusCode(StatusCode.SC_200_OK);
		hr.setHeaderField(HeaderField.X_ADMIN_PROTOCOL, HttpConstants.ADMIN_PROTOCOL);
		hr.setHeaderField(HeaderField.X_ADMIN_NEXT_URI , "/CEH/cehocp");
		hr.setHeaderField(HeaderField.CONTENT_TYPE, HttpConstants.ADMIN_CONTENT_TYPE);
		hr.setHeaderField(HeaderField.TARGET_APPLICATION, hr.targAppAid(aidInstanceRfm)); // D27600002841070101020002B0002601
		cmd.addBlob(ConversionUtil.byteArray("00A40000022FE200B0000006"));
		hr.setContentField(new ContentField(cmd));

		// *********************** CLEAR STRUCTURE ***********************
		Log.writePostBlock();

		testcaseEnd();
	}

	static {
		// testcaseID = 9110
		TestcaseInfo info = new TestcaseInfo();
		info.setInfo(TestcaseInfo.TITLE, "send buffer size in Triggering SMS less then 1500 bytes");
		info.setTestcaseNo(1);
		info.setInfo(TestcaseInfo.DESCRIPTION, "Open_ChannelValid: send buffer size in Triggering SMS less then 1500 bytes");
		info.setInfo(TestcaseInfo.STATUS, "implemented");
		info.setInfo(TestcaseInfo.STATUS_DESCRIPTION, "(cb,09.01.13) 8634 added as recommended TB id");
		info.setInfo(TestcaseInfo.ID, "9110");
		info.setInfo(Selector.SELECTIONRULE, "GlobalPlatform221AmendmentB_Supported");
		testcaseInfos.put("tc_002", info);
	}

	// [testcase_start: 9110]
	public void tc_002() throws Exception {
		testcaseBegin(testcaseInfos.get("tc_002"));
		// ************************* PREPARATION *************************
		Log.writePreBlock();

		AdminAgentTools adminAgentTools;
		String bearerDescription;
		int bufferSizeAdmin;
		String networkAccessName;
		String loginName;
		String loginPasswort;
		String tcpPort;
		String dataDestinationAddressIPv4;
		ConnectionParameters connectionParameter;

		adminAgentTools = new AdminAgentTools();

		// Type=GPRS, Parameter=010101010102
		bearerDescription = "02010101010102";
		// Set Buffer Size
		bufferSizeAdmin = 1500;
		// Network access name
		networkAccessName = "morpho.com";
		loginName = "admin";
		loginPasswort = "root";
		// Interface transport level: protocol=TCP, UICC in client mode,
		// port=9096
		tcpPort = "9096";
		dataDestinationAddressIPv4 = "80.66.10.152";

		connectionParameter = new ConnectionParameters(bearerDescription, bufferSizeAdmin, networkAccessName, loginName, loginPasswort, tcpPort,
				dataDestinationAddressIPv4);

		SecurityParameters securtiyParameters = new SecurityParameters();
		securtiyParameters.setValue("143839333930313030303030313239353036393033024001");

		HttpPostParameters getHttpPostParameters = new HttpPostParameters();
		getHttpPostParameters.setValue("8A1138302E36362E31302E3230303A383038308B033030378C0B2F4345482F6365686F6370");

		AdminAgentConfigurationParameters acp = new AdminAgentConfigurationParameters(connectionParameter, securtiyParameters, adminAgentTools
				.getDefaultConnectionOpener().getAdminTrigger().getRetryPolicyParameters(), getHttpPostParameters);

		CardManagementTestApplets.HttpAdminTrigger.init(true);
		ILoadFile loadFile = CardManagementTestApplets.HttpAdminTrigger.getLoadFile();
		IssuerSecurityDomain issuerSecurityDomain = (IssuerSecurityDomain) OffCardManager.getInstance().getAppletInstance("D27600002841010101010189000000");

		AppletManager appletManager = new AppletManager(this);
		TriggerApplet095 triggerApi = new TriggerApplet095(acp);

		triggerApi.loadAndInstall(loadFile, issuerSecurityDomain, this);
		appletManager.selectCM();
		Command command = new Command("IFE", "80E610001C09A00000015153504111000DD27600002851F0901095018903000000", "**");
		addCmd(command);
		triggerApi.openChannel(this);
		triggerApi.commandCreateArray(1024, this);
		triggerApi.cmdSetData(this);
		triggerApi.cmdConfigureTest(false, this);

		// String appletAID = triggerApi.getAppletAID();

		// ***************************** TEST ****************************
		Log.writeExecuteBlock();

		ResetCommands.detectColdATR(this);

		// get trigger for opening BIP via SMS
		// HTTP over BIP on channel 3
		IScwsConnectionOpener bipOpener = new BipAdminConnectionOpener(acp.getConnectionParameters().getBufferSizeAsInt(), triggerApi);
		HttpConnection httpConnection = new HttpConnection(new BipConnection(3, bipOpener));

		// add TLS security to HTTP
		httpConnection.setTlsLayer(new ClientTls(securtiyParameters, "0DB76915A80ED3F5272DA0809EFDB7E94F3B4068E9D02C1D",
				Ciphersuite.TLS_PSK_WITH_NULL_SHA256));
			//0DB76915A80ED3F5272DA0809EFDB7E94F3B4068E9D02C1D
		HttpRequest initialPost = httpConnection.receiveHttpRequest(this);
		

		Blob cmd;
		HttpResponse hr;
		String aidInstanceRfm = "D27600002841070101020005B0002301";

		cmd = new Blob();

		hr = new HttpResponse();
		hr.setStatusCode(StatusCode.SC_200_OK);
		hr.setHeaderField(HeaderField.X_ADMIN_PROTOCOL, HttpConstants.ADMIN_PROTOCOL);
		hr.setHeaderField(HeaderField.X_ADMIN_NEXT_URI , "/CEH/cehocp");
		hr.setHeaderField(HeaderField.CONTENT_TYPE, HttpConstants.ADMIN_CONTENT_TYPE);
		hr.setHeaderField(HeaderField.TARGET_APPLICATION, hr.targAppAid(aidInstanceRfm)); // D27600002841070101020002B0002601
		cmd.addBlob(ConversionUtil.byteArray("00A40000022FE200B0000006"));
		hr.setContentField(new ContentField(cmd));

		httpConnection.send(hr, this);

		/*cmd = new Blob();

		hr = new HttpResponse();
		hr.setStatusCode(StatusCode.SC_200_OK);
		hr.setHeaderField(HeaderField.X_ADMIN_PROTOCOL, HttpConstants.ADMIN_PROTOCOL);
		// hr.setHeaderField(HeaderField.X_ADMIN_NEXT_URI , "");
		hr.setHeaderField(HeaderField.CONTENT_TYPE, HttpConstants.ADMIN_CONTENT_TYPE);
		hr.setHeaderField(HeaderField.TARGET_APPLICATION, hr.targAppAid(aidInstanceRfm)); // D27600002841070101020002B0002601
		cmd.addBlob(ConversionUtil.byteArray("A0A40000022FE2A0B0000008"));
		hr.setContentField(new ContentField(cmd));

		httpConnection.send(hr, this);*/

		// initialPost.revertChunked();
		// *********************** CLEAR STRUCTURE ***********************
		Log.writePostBlock();

		testcaseEnd();
	}
}
