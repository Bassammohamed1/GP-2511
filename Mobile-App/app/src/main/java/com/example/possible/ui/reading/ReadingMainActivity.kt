package com.example.possible.ui.reading

import android.content.Intent
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import com.example.possible.databinding.ActivityReadingMainBinding

class ReadingMainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityReadingMainBinding
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityReadingMainBinding.inflate(layoutInflater)
        enableEdgeToEdge()
        // read only a static text
        binding.readTextBtn.setOnClickListener {
            val intent = Intent(this, ReadTextActivity::class.java)
            startActivity(intent)
        }
        //read custom text that user entered
        binding.enterCustomTextBtn.setOnClickListener {
            val intent = Intent(this, ReadCustomTextActivity::class.java)
            startActivity(intent)
        }
        //back to main activity
        binding.backArrowIV.setOnClickListener{
            this.finish()
        }
        setContentView(binding.root)

    }
}