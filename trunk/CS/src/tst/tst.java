package tst;

import core.RequestHeader;
import builtintypes.NodeId;
import core.MessageSecurityMode;
import utils.CryptoUtil;

public class tst {

	@SuppressWarnings("static-access")
	public static void main(String[] args) {

		RequestHeader req = new RequestHeader();
		NodeId id = new NodeId(69,9257);
		req.setAuthenticatonToken(id);
		System.out.print(MessageSecurityMode.class);
		CryptoUtil cry = new CryptoUtil();
		byte[] Nonce = cry.createNonce(2);
		System.out.println(Nonce);

	}

}
