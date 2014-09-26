package org.simalliance.openmobileapi.test;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


public class CmdTranslate {
	
	public String hexStringToByte(String s)
	{
		if(s.length() == 1)
		{
			return "0"+s;
		}
		return s;
	}
	
	public String hexStringToByte(int i)
	{
		String s = Integer.toString(i);
		if(s.length() == 1)
		{
			return "0"+s;
		}
		return s;
	}
	
	public String getCmd(String[] args) throws UnsupportedEncodingException
	{	
		String result = "";
		String after = "";
		List<String> tmp = new ArrayList<String>();
		for (String arg:args){
		tmp.add(arg);
		}
		Collections.reverse(tmp);
		for(String arg: tmp)
		{	
		
			if (arg.length() >2)
			{
				
				result = arg.substring(0,2) + hexStringToByte(after.length()/2+Integer.toHexString(arg.substring(2, arg.length()).length()/2))+arg.substring(2, arg.length())+result;
				after = result;
			}
			if (arg != "," && arg.length() == 2)
			{	
				if (after.length()/2 == 0)
				{
					result = arg + result;
					after = result;
				}
				else{
				result = arg + hexStringToByte((after.length()/2))+result;
				after = result;
				}
			}
		}
		
		return result;
	}
	
	public String getParam (String deviceName)
	{
		if (deviceName.equals("TempSensor"))
		{
			return "0001";
		}
		if (deviceName.equals("DoorLock"))
		{
			return "0002";
		}
		if (deviceName.equals("CafeMaker"))
		{
			return "0003";
		}
		else{
		return "Error: "+ deviceName;
		}
	}
	
	public byte[] stringToByteArray (String s) {
	    byte[] byteArray = new byte[s.length()];
	    for (int i = 0; i < s.length(); i++) {
	        byteArray[i] = (byte) s.charAt(i);
	    }
	    return byteArray;
	}
	
	public String[] getCmdTlv(String function, String parameter)
	{

		if (function == "GetValue")
		{	
	
				String[]result = {"90","91","92"};
				return result;
		}
		if (function == "SetSub")
		{	
	
				String[]result = {"90","91","93"+"9A"+parameter};
				return result;
		}
		if (function == "GetRecord")
		{	
	
				String[]result = {"90","91","94"};
				return result;
		}
		if (function == "Open")
		{	
	
				String[]result = {"90","91","95"};
				return result;
		}
		if (function == "AddWater")
		{	
	
				String[]result = {"90","91","96"};
				return result;
		}
		if (function == "AddCafe")
		{	
	
				String[]result = {"90","91","97"};
				return result;
		}
		if (function == "MakeCafe")
		{	
	
				String[]result = {"90","91","98"};
				return result;
		}
		if (function == "GrantAccess")
		{	
	
				String[]result = {"90","91","99","9B"+parameter};
				return result;
		}
		return null;
		

	
	}
	
	public static String byteArrayToHexString(byte in[]) {

		byte ch = 0x00;

		int i = 0;

		if (in == null || in.length <= 0)
			return null;

		String pseudo[] = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
				"A", "B", "C", "D", "E", "F" };

		StringBuffer out = new StringBuffer(in.length * 2);

		while (i < in.length) {
			ch = (byte) (in[i] & 0xF0); // Strip off high nibble

			ch = (byte) (ch >>> 4); // shift the bits down

			ch = (byte) (ch & 0x0F); // must do this is high order bit is on!

			out.append(pseudo[(int) ch]); // convert the nibble to a String

			ch = (byte) (in[i] & 0x0F); // Strip off low nibble

			out.append(pseudo[(int) ch]); // convert the nibble to a String

			i++;
		}

		String rslt = new String(out);

		return rslt;

	}
	
	public String processStr(String str)
	{
		StringBuilder builder = new StringBuilder("");
		for (char achar: str.toCharArray())
		{
			builder.append("0");
			builder.append(achar);
			
		}
		return builder.toString();
	}
	
	
	
}
