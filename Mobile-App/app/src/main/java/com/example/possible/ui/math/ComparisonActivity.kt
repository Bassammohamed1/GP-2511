package com.example.possible.ui.math

import android.os.Bundle
import android.os.Handler
import android.view.View.VISIBLE
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import com.example.possible.databinding.ActivityComparisionBinding
import com.example.possible.repo.local.MathQuestions
import com.example.possible.repo.local.SharedPref
import com.example.possible.util.TestDecoder

class ComparisonActivity : AppCompatActivity() {
    private lateinit var binding: ActivityComparisionBinding
    private lateinit var comparison:Triple<Int,Int,String>
    private var numOfQuestion=0
    private lateinit var pref: SharedPref
    private var level=""
    override fun onCreate(savedInstanceState: Bundle?) {
        binding = ActivityComparisionBinding.inflate(layoutInflater)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        pref= SharedPref(this)
        binding.biggerThan.text=">"
        binding.smallerThan.text="<"
        binding.equal.text="="
         level = intent.getStringExtra("level")!!
        comparison=getComparison(level)
        setQuestionView(comparison)

        handleOptions()
        handleSignView()
        checkResult()
        setContentView(binding.root)
    }
    private fun setTheSign(sign: String) {
     binding.sign.text = sign
    }
    private fun handleSignView() {
        binding.sign.setOnClickListener{
            if(binding.sign.text != "") {
                binding.sign.text = ""
            }
        }
    }
    private fun handleOptions() {
        binding.biggerThan.setOnClickListener {
            setTheSign(">")
        }
        binding.smallerThan.setOnClickListener {
            setTheSign("<")
        }
        binding.equal.setOnClickListener {
            setTheSign("=")
        }
        binding.backArrowIV.setOnClickListener {
            finish()
        }
        binding.changeQues.setOnClickListener{
            comparison=getComparison(level)
            setQuestionView(comparison)
        }
    }
    private fun getComparison(level:String):Triple<Int,Int,String>{
        return if(level == "beginner") {
             MathQuestions.getRandomComparison(MathQuestions.simpleComparisons)
        }
        else
        {
             MathQuestions.getRandomComparison(MathQuestions.proComparisons)
        }
    }
    private fun setQuestionView(comparison: Triple<Int, Int, String>) {
        binding.firstNumber.text = comparison.first.toString()
        binding.secondNumber.text = comparison.second.toString()
        binding.sign.text = ""
    }
    private fun checkResult(){
        binding.done.setOnClickListener{
            if(isItFromSettingTest()){
                getTheQuestionOnDone(numOfQuestion)
                finish()
            }
            else{
            if(binding.sign.text == comparison.third){
                binding.celeprationAnim.visibility = VISIBLE
                binding.celeprationAnim.playAnimation()
                Handler().postDelayed({
                    DialogBuilder.showSuccessDialog(this,"Bravooo!","next",onConfirm = {
                        comparison=getComparison(level)
                        setQuestionView(comparison)
                    })
                },200)

            }
            else{
                DialogBuilder.showErrorDialog(this,"Wrong Answer","Try Again")
            }
            }
        }
    }
    private fun isItFromSettingTest():Boolean{
        numOfQuestion = intent.getIntExtra("noOfQuestion",0)
        return numOfQuestion!=0

    }
    private fun getTheQuestionOnDone(numOfQuestion:Int){
        val comparison = TestDecoder.encodeComparison(comparison)
        setWhichQuestion(comparison,numOfQuestion)
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