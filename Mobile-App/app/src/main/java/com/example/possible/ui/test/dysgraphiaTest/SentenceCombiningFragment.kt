package com.example.possible.ui.test.dysgraphiaTest

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import com.example.possible.databinding.FragmentSentenceCombiningBinding
import com.example.possible.model.SentenceCombining
import com.example.possible.repo.local.SentenceQuestions
import com.example.possible.util.TestDecoder


class SentenceCombiningFragment : Fragment() {
   private lateinit var binding: FragmentSentenceCombiningBinding
   private lateinit var sentence1: String
   private lateinit var sentence2: String
   private lateinit var combinedSentence: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
        }
    }
     fun newInstance(ques :String): SentenceCombiningFragment {
        val fragment = SentenceCombiningFragment()
        val args = Bundle()
        args.putString("ques", ques)
        fragment.arguments = args
        return fragment
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        // Inflate the layout for this fragment
        binding = FragmentSentenceCombiningBinding.inflate(inflater, container, false)
        val sentence = arguments?.getString("ques")

        if(sentence!=""){
            val sentenceQues = TestDecoder.decodeSentenceCombining(sentence!!)
            getTheSentences(sentenceQues)
        }
        else{
            val sentenceQues = SentenceQuestions.getRandomCombingSentence()
            getTheSentences(sentenceQues)
        }
        setView()
        setControllers()
        return binding.root
    }
    private fun getTheSentences(sentence:SentenceCombining) {
        sentence1 = sentence.firstSentence
        sentence2 = sentence.secondSentence
        combinedSentence = sentence.combinedSentence
    }

    private fun setView(){
        binding.firstSentence.text = sentence2
        binding.secondSentence.text = sentence1
        binding.combinedSentence.text =""
    }
    private fun setControllers()  {
        binding.firstSentence.setOnClickListener{
            if (binding.firstSentence.text.toString() != "") {
            val text = binding.firstSentence.text.toString()
            binding.firstSentence.text =""
            handleCombinedText(text)}
        }
        binding.secondSentence.setOnClickListener{
            if (binding.secondSentence.text.toString() != "") {
            val text = binding.secondSentence.text.toString()
            binding.secondSentence.text =""
            handleCombinedText(text)
            }
        }
        binding.combinedSentence.setOnClickListener{
            binding.firstSentence.text = sentence1
            binding.secondSentence.text = sentence2
            binding.combinedSentence.text = ""
        }
    }
    @SuppressLint("SetTextI18n")
    private fun handleCombinedText(text: String){
        val combinedText = binding.combinedSentence.text
        if (combinedText.isNotEmpty()) {
            binding.combinedSentence.text = "$combinedText $text"
        } else {
            binding.combinedSentence.text = text
        }
    }
    fun returnResult(): Int {
        return if (binding.combinedSentence.text.toString() == combinedSentence) {
            2
        } else {
            0

        }
    }
    fun getTheQuestion():String{
        val combinedText = SentenceCombining(sentence1,sentence2,combinedSentence)
        return TestDecoder.encodeSentenceCombining(combinedText)
    }


}