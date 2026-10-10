package com.cybershield.ai;
import android.app.Activity; import android.os.Bundle; import android.widget.TextView;
public class MainActivity extends Activity { public void onCreate(Bundle b){super.onCreate(b); TextView t=new TextView(this); t.setText("CyberShield AI\nARM64 Android deployment shell.\nPin ExecuTorch, add Llama .pte/tokenizer, then integrate LlmModule."); t.setPadding(32,64,32,32); setContentView(t);} }
