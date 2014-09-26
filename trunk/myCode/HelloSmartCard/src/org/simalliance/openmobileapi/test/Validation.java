package org.simalliance.openmobileapi.test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.text.Html;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.method.ScrollingMovementMethod;
import android.text.style.ForegroundColorSpan;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup.LayoutParams;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.TextView.BufferType;
import android.widget.Toast;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Spinner;
import android.widget.AdapterView.OnItemSelectedListener;
 










import org.bouncycastle.util.encoders.Hex;
import org.simalliance.openmobileapi.*;

public class Validation extends Activity implements SEService.CallBack, OnItemSelectedListener {

	final String LOG_TAG = "Smart Home";
	
	/** Open Mobile API service. */
	SEService scservice = null;
	String cardreader = "";
	Channel logicalChannel = null;

	private EditText name;
	private EditText pwd;
	
	private TextView console;
	
	private Button btn;
	private Button start;
	private Button resetBtn;
	private Button newBtn;
	
	UiDesign myUI = new UiDesign();
	CmdTranslate cmd = new CmdTranslate();
	
	@Override
	public void onCreate(Bundle savedInstanceState) {

		super.onCreate(savedInstanceState);
		// do layout and UI stuff
		setContentView(R.layout.welcome);
		console = (TextView) findViewById(R.id.textView1);
		
		btn =(Button)findViewById(R.id.widget37);
		start = (Button)findViewById(R.id.widget38);
		resetBtn = (Button)findViewById(R.id.Button01);
		newBtn = (Button)findViewById(R.id.Button02);
		
	    pwd = (EditText)findViewById(R.id.widget36);
	    
		scservice = new SEService(this, this);

		start.setOnClickListener(new OnClickListener(){  
			    
	            public void onClick(View v) {  
	            	try {          	
	            		 performSelectOpt(scservice);
					} catch (Exception e) {
						Log.e(LOG_TAG, "Error occured:", e);
						return;
					}     
	               // intent.setClass(Validation.this, MainActivity.class);  
	               // startActivity(intent);  
	               // finish();    
	            }  
	              
	        });  
		
		newBtn.setOnClickListener(new OnClickListener(){  
		    
            public void onClick(View v) {  
            	try {          	
            		 performNewPin(scservice);
				} catch (Exception e) {
					Log.e(LOG_TAG, "Error occured:", e);
					return;
				}     
               // intent.setClass(Validation.this, MainActivity.class);  
               // startActivity(intent);  
               // finish();    
            }  
              
        });  
		resetBtn.setOnClickListener(new OnClickListener(){  
		    
            public void onClick(View v) {  
            	try {          	
            		 performUnblockOpt(scservice);
				} catch (Exception e) {
					Log.e(LOG_TAG, "Error occured:", e);
					return;
				}     
               // intent.setClass(Validation.this, MainActivity.class);  
               // startActivity(intent);  
               // finish();    
            }  
              
        });  
	
        btn.setOnClickListener(new OnClickListener(){  
        	int verifyResult = 0;
            public void onClick(View v) {  
            	try {          		
            		
            		 Intent intent = new Intent();           			  	
            		 verifyResult = performVerifyOpt(scservice);
            		 if (verifyResult == 1)
            		 {
            			  	intent.setClass(Validation.this, MainActivity.class);  
            			  	startActivity(intent);  
            			  	finish(); 
            		 }
            		 if (verifyResult == 3)
            		 {
            			  	intent.setClass(Validation.this, BlockActivity.class);  
            			  	startActivity(intent);  
            			  	finish(); 
            		 }
            		
     			  	 
				} catch (Exception e) {
					Log.e(LOG_TAG, "Error occured:", e);
					return;
				}     
  
            }  
              
        });  
    } 

	void performSelectOpt(SEService service) throws IOException {
		try{		
			Reader[] readers = service.getReaders();
			cardreader = readers[0].getName();

			boolean isPresent = readers[0].isSecureElementPresent();
			Log.d(LOG_TAG, isPresent ? " present\n" : " absent\n");

			Session session = readers[0].openSession();
			//01 01 01 01 21 01 01 22
			final byte[] hellosimcard = new byte[] {(byte)0x01,(byte)0x01,(byte)0x01,(byte)0x01,(byte)0x21,(byte)0x01,(byte)0x01,(byte)0x22};
			logicalChannel = session.openLogicalChannel(hellosimcard);			
			//performVerifyOpt(service);
			console.append("Service Created \n");
			
		 }
		catch (Exception ex) 
		{
			console.append(ex.getMessage()+"\n");
		}
	}

	
	
	
	//put SEND	
	@Override
	protected void onDestroy() {
		if (scservice != null && scservice.isConnected()) {
			scservice.shutdown();
		}
		super.onDestroy();
	}

public void serviceConnected(SEService service) {
		Log.i(LOG_TAG, "entry: seviceConnected()");
	}

	    public void onNothingSelected(AdapterView<?> arg0) {
	        // TODO Auto-generated method stub
	         
	    }


		public void onItemSelected(AdapterView<?> arg0, View arg1, int arg2,
				long arg3) {
			// TODO Auto-generated method stub
			
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
		
		int performVerifyOpt(SEService service) {
				
			try {
       		 	String input = pwd.getText().toString();       
       		 	String command =("A01100000"+Integer.toString(input.length())+cmd.processStr(input)); 
       		 	byte[] cmdApdu = Hex.decode(command);
				byte[] result = logicalChannel.transmit(cmdApdu);				
			
		
			if (byteArrayToHexString(result).equals("9000"))
			{	
				String s = "VerfiyPin Passed";
				console.append(myUI.getStyle("VerfiyPin Passed \n",9,s.length(), "GREEN"));
				return 1;
			}
			if (byteArrayToHexString(result).equals("6983"))
			{	
				String s = "Phone Blocked";
				console.append(myUI.getStyle("Phone Blocked \n", 6,s.length(),"RED") );
				return 3;
			}
			if (byteArrayToHexString(result).equals("6984") ||byteArrayToHexString(result).equals("63C0"))
			{	
				String s = "VerfiyPin Failed";
				console.append(myUI.getStyle("VerfiyPin Failed \n",9,s.length() ,"RED") );
				return 0;
			}
					
			}
			catch (Exception ex) 
			{
				console.append("Param ERROR: "+ex.getMessage()+"\n");

			}
			return 0;
		}
		
		void performUnblockOpt(SEService service) {
			try {
				byte[] cmdApdu = Hex.decode ("A0130000");
				byte[] result = logicalChannel.transmit(cmdApdu);

			if (byteArrayToHexString(result).equals("9000"))
			{
				String s = "Phone Unlocked";
				console.append(myUI.getStyle("Phone Unlocked \n",6,s.length()  ,"GREEN") );
			}
			else
			{
				String s ="Unlock Phone Failed";
				console.append(myUI.getStyle("Unlock Phone Failed \n",12,s.length() ,"RED") );
		
			}
				
			} catch (Exception ex) {
				console.append(ex.getMessage()+"\n");
			}

		}
		
		void performNewPin(SEService service) {
			try {
				byte[] cmdApdu = Hex.decode ("A0130000");
				byte[] result = logicalChannel.transmit(cmdApdu);

			
			if (byteArrayToHexString(result).equals("9000"))
			{	
				String s ="NewPin Saved";
				console.append(myUI.getStyle("NewPin Saved \n",6,s.length() ,"GREEN") );
			}
		
			else
			{
				String s = "ResetPin Failed";
				console.append(myUI.getStyle("ResetPin Failed \n", 9,s.length(),"RED") );
		
			}
				
			} catch (Exception ex) {
				console.append(ex.getMessage()+"\n");
			}

		}
}