package org.simalliance.openmobileapi.test;

import org.simalliance.openmobileapi.SEService;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.TextView;

public class BlockActivity extends Activity  {

	private TextView block;
	
public void onCreate(Bundle savedInstanceState) {

	super.onCreate(savedInstanceState);
	// do layout and UI stuff
	setContentView(R.layout.block);
	block = (TextView)findViewById(R.id.widget32);

	
}

}