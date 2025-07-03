package com.example.possible.ui.math

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.view.View.GONE
import android.view.View.VISIBLE
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import com.example.possible.databinding.ActivityMainMathBinding

class MainMathActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainMathBinding
    private lateinit var Handler: Handler
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainMathBinding.inflate(layoutInflater)
        Handler = Handler()
        enableEdgeToEdge()
        var nameOFOperation=""
        var beginnerOrProf: String

        binding.proIV.setOnClickListener{
            beginnerOrProf="pro"
            goTOActivity(nameOFOperation,beginnerOrProf)
            hideTheView()
        }
        binding.beginnerIV.setOnClickListener{
            beginnerOrProf="beginner"
            goTOActivity(nameOFOperation,beginnerOrProf)
            hideTheView()
        }


        binding.AddingBtn.setOnClickListener {
            nameOFOperation="Adding"
            viewBeginnerOrProf()

        }
        binding.subtractingBtn.setOnClickListener {
            nameOFOperation="subtracting"
            viewBeginnerOrProf()

        }
        binding.comparisonBtn.setOnClickListener {
            nameOFOperation="comparison"
            viewBeginnerOrProf()

        }
        binding.arithmeticSeqBtn.setOnClickListener {
            nameOFOperation="arithmeticSeq"
            viewBeginnerOrProf()

        }
        binding.hideView.setOnClickListener {
            hideTheView()

        }
        binding.backArrowIV.setOnClickListener {
            finish()
        }
        setContentView(binding.root)
    }

     private fun viewBeginnerOrProf() {
         binding.beginnerOrProf.visibility= VISIBLE
         binding.btns.visibility= GONE
         binding.beginnerOrProf.animate().scaleX(0f).scaleY(0f).setDuration(0).start()
         binding.beginnerOrProf.animate().scaleX(1f).scaleY(1f).setDuration(500).start()
     }

    private fun hideTheView(){
        Handler.postDelayed({
            binding.beginnerOrProf.animate().scaleX(0f).scaleY(0f).setDuration(300).withEndAction{
                binding.btns.visibility= VISIBLE
                binding.beginnerOrProf.visibility= GONE
            }.start()
        },200)

    }


    private fun goToAddingActivity(name:String, level:String){
        val intent = Intent(this, AddingActivity::class.java)
        intent.putExtra("operationName",name)
        intent.putExtra("operationLevel",level)
        startActivity(intent)
    }
    private fun goToComparisonActivity(level:String){
        val intent = Intent(this, ComparisonActivity::class.java)
        intent.putExtra("level",level)
        startActivity(intent)
    }
    private fun goToArithmeticSeqActivity(level:String){
        val intent = Intent(this, ArithmeticSequenceActivity::class.java)
        intent.putExtra("level",level)
        startActivity(intent)
    }
    private fun goTOActivity(name:String,level:String){
        when(name){
            "Adding","subtracting"->goToAddingActivity(name,level)
            "comparison"->goToComparisonActivity(level)
            "arithmeticSeq"->goToArithmeticSeqActivity(level)
        }
    }

}