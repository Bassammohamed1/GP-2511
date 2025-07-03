package com.example.possible.ui.test.dyscalculiaTest

import android.annotation.SuppressLint
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import com.example.possible.R
import com.example.possible.databinding.FragmentAddingBinding
import com.example.possible.model.Adding
import com.example.possible.util.TestDecoder
import com.example.possible.util.adapter.ResultAdapter

class AddingFragment : Fragment() {
    private lateinit var binding: FragmentAddingBinding
    private lateinit var resultArray: ArrayList<Int>
    private var question : Adding = Adding(0,0,0,0)
     fun getInstance(question:String,operationType:String):AddingFragment{
        val fragment=AddingFragment()
        val bundle=Bundle()
        bundle.putString("question",question)
        bundle.putString("operationType",operationType)
        fragment.arguments=bundle
        return fragment
    }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {

        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        resultArray= arrayListOf()
        // Inflate the layout for this fragment
        binding= FragmentAddingBinding.inflate(layoutInflater,container,false)
        val questionAsString=arguments?.getString("question")
        val linearLayoutManager = LinearLayoutManager(requireContext(), LinearLayoutManager.HORIZONTAL, false)
        binding.resultAdapter.layoutManager = linearLayoutManager

        val opType= arguments?.getString("operationType")!!
         question = TestDecoder.decodeAdding(questionAsString!!)
        setQuestionView(question,opType)

        return binding.root
    }
    @SuppressLint("SetTextI18n")
    private fun setQuestionView(question:Adding,op:String){
        binding.firstNumber.text= question.a.toString()
        binding.secondNumber.text= question.b.toString()
        if(op=="Adding"){binding.sign.setImageResource(R.drawable.plus_sign)
        } else {binding.sign.setImageResource(R.drawable.sign_minus)}
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
        binding.resultAdapter.adapter= ResultAdapter(resultArray)
    }
    private fun getTheSum(): Int {
        var sum = 0
        try {
            if (!::resultArray.isInitialized || resultArray.isEmpty()) {
                throw IllegalStateException("resultArray is not initialized or is empty.")
            }

            var dub = 1
            var i = 0
            while (i < resultArray.size) {
                sum += resultArray[i] * dub
                dub *= 10
                i++
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return sum
    }

    fun getResult():Int{
        return if( question.c == getTheSum()) 2 else 0
    }

}