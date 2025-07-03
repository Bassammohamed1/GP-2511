package com.example.possible.ui.test.dyscalculiaTest

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.example.possible.databinding.FragmentComparisionBinding
import com.example.possible.util.TestDecoder


class ComparisonFragment : Fragment() {
    private lateinit var binding : FragmentComparisionBinding
    private lateinit var question  : Triple<Int,Int,String>
    fun getInstance (comp:String): ComparisonFragment{
        val fragment=ComparisonFragment()
        val bundle=Bundle()
        bundle.putString("comp",comp)
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
        binding= FragmentComparisionBinding.inflate(layoutInflater,container,false)
        val comp=arguments?.getString("comp")
        question = TestDecoder.decodeComparison(comp!!)
        setTheQuestion()
        handleOptions()
        // Inflate the layout for this fragment
       return binding.root
    }

    @SuppressLint("SetTextI18n")
    private fun setTheQuestion(){
        binding.biggerThan.text=">"
        binding.smallerThan.text="<"
        binding.equal.text="="
        binding.firstNumber.text= question.first.toString()
        binding.secondNumber.text= question.second.toString()
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
        handleSignView()

    }
    fun getResult(): Int {
        return try {
            if (!::binding.isInitialized) {  // تأكد إن الـ binding متعرف
                throw IllegalStateException("Binding is not initialized.")
            }

            if (question.third == binding.sign.text.toString()) {
                2
            } else {
                0
            }
        } catch (e: Exception) {
            e.printStackTrace()
            0
        }
    }

}