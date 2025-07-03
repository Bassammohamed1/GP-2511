package com.example.possible.ui.specialist.tests

import android.content.Intent
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.example.possible.R
import com.example.possible.databinding.ActivityTestTypesBinding
import com.example.possible.ui.test.dysgraphiaTest.SentenceMainActivity

class TestTypesActivity : AppCompatActivity() {
    private lateinit var binding: ActivityTestTypesBinding
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityTestTypesBinding.inflate(layoutInflater)
        enableEdgeToEdge()
        setContentView(binding.root)
        setupControllers()
    }
    private fun setupControllers(){
        binding.Dyslexia.setOnClickListener {
            goToSetExam("CCC","Dyslexia")

        }
        binding.DyscalculiaC.setOnClickListener {
            goToSetExam("AAA","Dyscalculia")
        }
        binding.Dysgraphia.setOnClickListener {
            goToSetExam("BBB","Dysgraphia")
        }
        binding.backArrowIV.setOnClickListener {
            finish()
        }



    }
    private fun goToSetExam(name:String,type:String){
        val intent = Intent(this, SettingTestActivity::class.java)
        intent.putExtra("type",type)
        intent.putExtra("name",name)
        startActivity(intent)

    }
}