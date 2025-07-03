package com.example.possible.ui.test.dysgraphiaTest

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.example.possible.databinding.FragmentSentenceCompletingBinding
import com.example.possible.model.SentenceCombining
import com.example.possible.model.SentenceCompleting
import com.example.possible.repo.local.SentenceQuestions
import com.example.possible.util.TestDecoder


class SentenceCompletingFragment : Fragment() {
    private lateinit var binding: FragmentSentenceCompletingBinding
    private var sentence1 = ""
    private var sentence2 = ""
    private var words = mutableListOf<String>()
    private var wordToAdd = ""
    private var chosenWord = ""


    fun newInstance(ques :String): SentenceCompletingFragment {
        val fragment = SentenceCompletingFragment()
        val args = Bundle()
        args.putString("ques", ques)
        fragment.arguments = args
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
        // Inflate the layout for this fragment
        binding = FragmentSentenceCompletingBinding.inflate(inflater , container , false)
        val sentence = arguments?.getString("ques")!!

        if(sentence!=""){
            val sentenceQues = TestDecoder.decodeSentenceCompleting(sentence)
            setSentences(sentenceQues)
        }
        else{
            val sentenceQues = SentenceQuestions.getRandomCompletingSentence()
            setSentences(sentenceQues)
        }
        setView()
        setControllers()

        return binding.root
    }
    private fun setSentences(ques :SentenceCompleting){
        sentence1 = ques.firstSentence
        sentence2 = ques.secondSentence
        wordToAdd = ques.theWordToAdd
        words = ques.listToChooseFrom.toMutableList()
    }
    @SuppressLint("SetTextI18n")
    private fun setView(){
        binding.sentenceToComplete.text = "$sentence1 ....... $sentence2"
        binding.first.text = words[0]
        binding.second.text = words[1]
        binding.third.text = words[2]
        binding.Fourth.text = words[3]
    }

    private fun  setControllers(){
        binding.first.setOnClickListener{
            setChosenWord(binding.first.text.toString())
        }
        binding.second.setOnClickListener{
            setChosenWord(binding.second.text.toString())
        }
        binding.third.setOnClickListener{
            setChosenWord(binding.third.text.toString())
        }
        binding.Fourth.setOnClickListener {
        setChosenWord(binding.Fourth.text.toString())
        }
    }

    @SuppressLint("SetTextI18n")
    private fun setChosenWord(word:String){
        binding.sentenceToComplete.text = "$sentence1 $word $sentence2"
        chosenWord = word
    }

    fun returnResult(): Int {
        return if (chosenWord == wordToAdd) {
            2
        } else {
            0
        }
    }
    fun getTheQuestion():String{
        val completedText = SentenceCompleting(sentence1,sentence2,wordToAdd,words)
        return TestDecoder.encodeSentenceCompleting(completedText)
    }


}