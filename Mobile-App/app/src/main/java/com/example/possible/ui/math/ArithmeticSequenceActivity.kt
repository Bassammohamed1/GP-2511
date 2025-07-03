package com.example.possible.ui.math

import DialogBuilder
import android.annotation.SuppressLint
import android.os.Bundle
import android.os.Handler
import android.view.View
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import com.example.possible.R
import com.example.possible.databinding.ActivityArithmeticSequenceBinding
import com.example.possible.repo.local.MathQuestions
import com.example.possible.repo.local.SharedPref
import com.example.possible.util.TestDecoder

class ArithmeticSequenceActivity : AppCompatActivity() {
    lateinit var binding: ActivityArithmeticSequenceBinding
    private var numOfQuestion=0
    private lateinit var pref: SharedPref
    private var firstResult = 0
    private var secondResult = 0
    private var sequence :List<Int> = emptyList()
    private var level=""
    override fun onCreate(savedInstanceState: Bundle?) {
        binding = ActivityArithmeticSequenceBinding.inflate(layoutInflater)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        level = intent.getStringExtra("level").toString()
        setContentView(binding.root)
        setSequence(level)
        pref= SharedPref(this)
        handleDone()
        binding.changeQues.setOnClickListener {
            handleChange()
        }
        binding.backArrowIV.setOnClickListener {
            finish()
        }
    }

    private fun getSequence(level: String): List<Int> {
       return if (level == "beginner") {
           MathQuestions.getRandomSequence(MathQuestions.simpleSequences)
       }
        else{
            MathQuestions.getRandomSequence(MathQuestions.proLevelSequences)
       }
    }
    @SuppressLint("SetTextI18n")
    private fun setSequence(level: String) {
        sequence = getSequence(level)
        binding.first.text = sequence[0].toString()+" ,   "
        binding.second.text = sequence[1].toString()+" ,  "
        binding.third.text = sequence[2].toString()+" ,  "
        binding.fivth.text = sequence[4].toString()+" ,  "
        binding.seventh.text = " ,  "+sequence[6].toString()
        firstResult = sequence[3]
        secondResult = sequence[5]
    }
    private fun handleCardBackground(card: View, expectedResult: Boolean) {
        if (expectedResult){
            card.setBackgroundResource(R.color.correct)
        }
        else{
            card.setBackgroundResource(R.color.error)
        }
    }
    private fun handleDone(){
        binding.done.setOnClickListener {
            if(isItFromSettingTest()){
                getTheQuestionOnDone(numOfQuestion)
                finish()
            }
            else{
            val firstInput = if(binding.fourth.text.toString().isNotEmpty()){
                binding.fourth.text.toString().toInt()
            } else{
                -1
            }
            val secondInput = if(binding.sixth.text.toString().isNotEmpty()){
                binding.sixth.text.toString().toInt()
            } else{
                -1
            }

            if(firstInput == firstResult && secondInput == secondResult){
                binding.celeprationAnim.visibility = View.VISIBLE
                binding.celeprationAnim.playAnimation()
                Handler().postDelayed({
                    DialogBuilder.showSuccessDialog(this,"Good boy!","next",onConfirm = {
                        handleChange()
                    })
                },200)
            }
            else{
                DialogBuilder.showErrorDialog(this,"Wrong Answer","Try Again")
            }
            handleCardBackground(binding.fourth, firstInput == firstResult)
            handleCardBackground(binding.sixth, secondInput == secondResult)

        }
        }
    }


    private fun handleChange(){
        setSequence(level)
        binding.fourth.text.clear()
        binding.sixth.text.clear()
        binding.celeprationAnim.visibility = View.GONE
        binding.celeprationAnim.cancelAnimation()
        binding.fourth.setBackgroundResource(R.color.white)
        binding.sixth.setBackgroundResource(R.color.white)
    }

    private fun isItFromSettingTest():Boolean{
        numOfQuestion = intent.getIntExtra("noOfQuestion",0)
        return numOfQuestion!=0

    }

    private fun getTheQuestionOnDone(numOfQuestion:Int){
        val sequence = TestDecoder.encodeArithmeticSequence(sequence)
        setWhichQuestion(sequence,numOfQuestion)
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