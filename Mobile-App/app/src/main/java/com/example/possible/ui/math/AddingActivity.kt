package com.example.possible.ui.math

import DialogBuilder
import android.os.Bundle
import android.os.Handler
import android.view.View.VISIBLE
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.example.possible.R
import com.example.possible.databinding.ActivityAddingBinding
import com.example.possible.model.Adding
import com.example.possible.repo.local.MathQuestions
import com.example.possible.repo.local.SharedPref
import com.example.possible.util.TestDecoder
import com.example.possible.util.adapter.ResultAdapter

class AddingActivity : AppCompatActivity() {
    lateinit var binding: ActivityAddingBinding
    private lateinit var question: Adding
    private lateinit var pref: SharedPref
    private lateinit var resultArray: ArrayList<Int>
    private var numOfQuestion=0
    private val  handler : Handler = Handler()
    override fun onCreate(savedInstanceState: Bundle?) {
        binding = ActivityAddingBinding.inflate(layoutInflater)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        pref= SharedPref(this)
        val operationType=intent.getStringExtra("operationName")
        val operationLevel=intent.getStringExtra("operationLevel")



        setTheQuestionView(operationType!!,operationLevel!!)

        binding.changeQues.setOnClickListener{
            setTheQuestionView(operationType,operationLevel)
        }

        val linearLayoutManager = LinearLayoutManager(this, LinearLayoutManager.HORIZONTAL, false)
        binding.resultAdapter.layoutManager = linearLayoutManager

        binding.done.setOnClickListener{
          if(isItFromSettingTest()){
              getTheQuestionOnDone(numOfQuestion)
              finish()
          }
          else{  val msg=if(question.c==getTheSum()) "true" else "wrong"
            if(msg=="true"){
                binding.celeprationAnim.visibility=VISIBLE
                binding.celeprationAnim.playAnimation()
                handler.postDelayed({
                    DialogBuilder.showSuccessDialog(this,"Excellent!","next",onConfirm = {
                        setTheQuestionView(operationType,operationLevel)
                    })
                },200)

            }
              else{
                  DialogBuilder.showErrorDialog(this,"Wrong Answer","Try to solve Again")
            }
          }

        }
        binding.backArrowIV.setOnClickListener{
            finish()
        }
        setContentView(binding.root)
    }
    private fun setTheQuestionView(type:String, level:String){
        question=theQuestion(type,level)
        binding.firstNumber.text=question.a.toString()
        binding.secondNumber.text=question.b.toString()
        val answerPlaces=question.resultPlaces
        val arr= when(answerPlaces){
            1-> arrayListOf(0)
            2->arrayListOf(0,0)
            3->arrayListOf(0,0,0)
            4->arrayListOf(0,0,0,0)
            5->arrayListOf(0,0,0,0,0)
            else->arrayListOf(0,0,0,0,0)
        }
        resultArray=arr
        binding.resultAdapter.adapter=ResultAdapter(resultArray)
    }
    private fun getTheSum():Int{
        var sum=0
        var dub=1
        var i=0
        while (i<resultArray.size){
            sum+=resultArray[i]*dub
            dub*=10
            i++
        }
        return sum
    }
    private fun theQuestion(type:String, level:String):Adding{
        if(type=="Adding"){
            binding.sign.setImageResource(R.drawable.plus_sign)
            return if(level=="beginner"){
                MathQuestions.getRandomQuestion(MathQuestions.simpleAddition)
            } else{
                MathQuestions.getRandomQuestion(MathQuestions.proAddition)
            }
        }
        else{
            binding.sign.setImageResource(R.drawable.sign_minus)
            return if(level=="beginner"){
                MathQuestions.getRandomQuestion(MathQuestions.simpleSubtraction)
            }
            else{
                MathQuestions.getRandomQuestion(MathQuestions.proSubtraction)
            }

            }
    }
    private fun isItFromSettingTest():Boolean{
        numOfQuestion = intent.getIntExtra("noOfQuestion",0)
        return numOfQuestion!=0

    }

    private fun getTheQuestionOnDone(numOfQuestion:Int){
        val ques = TestDecoder.encodeAdding(question)
        setWhichQuestion(ques,numOfQuestion)
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