package com.example.possible.ui.test.dysgraphiaTest

import android.os.Bundle
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.Fragment
import com.example.possible.R
import com.example.possible.databinding.ActivitySentenceMainBinding
import com.example.possible.repo.local.SharedPref
import com.example.possible.util.TestDecoder

class SentenceMainActivity : AppCompatActivity() {
    private lateinit var binding: ActivitySentenceMainBinding
    private lateinit var pref : SharedPref
    private var numOfQuestion=0
    private lateinit var question: String
    private var mode :String = ""
    var fragment = Fragment()
    override fun onCreate(savedInstanceState: Bundle?) {
        binding = ActivitySentenceMainBinding.inflate(layoutInflater)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(binding.root)
        pref = SharedPref(this)
        mode =intent.getStringExtra("mode").toString()

        if (mode == "combining"){
            fragment = SentenceCombiningFragment().newInstance("")
            supportFragmentManager.beginTransaction()
                .replace(R.id.frame, fragment)
                .commit()
        }
        else if (mode == "completing"){
            fragment = SentenceCompletingFragment().newInstance("")
            supportFragmentManager.beginTransaction()
                .replace(R.id.frame, fragment)
                .commit()
        }
        binding.done.setOnClickListener {
            if(isItFromSettingTest()){
                getTheQuestionOnDone(numOfQuestion)
                finish()
            }
            else{
                getTheResult()
            }
        }


    }


    private fun getTheResult(){
        if(fragment is SentenceCompletingFragment){
             val result = (fragment as SentenceCompletingFragment).returnResult()
            Toast.makeText(this, "  $result ", Toast.LENGTH_SHORT).show()
        }
        else if (fragment is SentenceCombiningFragment){
            val result = (fragment as SentenceCombiningFragment).returnResult()
            Toast.makeText(this," $result", Toast.LENGTH_SHORT).show()
        }
    }

    private fun isItFromSettingTest():Boolean{
        numOfQuestion = intent.getIntExtra("noOfQuestion",0)
        return numOfQuestion!=0

    }

    private fun getTheQuestionOnDone(numOfQuestion:Int){
        if(fragment is SentenceCompletingFragment){
            question = (fragment as SentenceCompletingFragment).getTheQuestion()
        }
        else if (fragment is SentenceCombiningFragment){
            question = (fragment as SentenceCombiningFragment).getTheQuestion()
        }
        setWhichQuestion(question,numOfQuestion)
    }
    private fun setWhichQuestion(ques:String,numOfQuestion:Int){
        when(numOfQuestion){
            1->{
                pref.setQ1(ques)
            }
            2->{
                pref.setQ2(ques)
            }
            3->{
                pref.setQ3(ques)
            }
            4->{
                pref.setQ4(ques)
            }
        }
    }

}