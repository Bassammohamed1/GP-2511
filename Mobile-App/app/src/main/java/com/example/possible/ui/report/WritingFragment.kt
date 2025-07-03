package com.example.possible.ui.report

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.example.possible.R
import com.example.possible.databinding.FragmentReadingBinding
import com.example.possible.databinding.FragmentWritingBinding

class WritingFragment : Fragment() {
    private lateinit var binding: FragmentWritingBinding
    fun newInstance(rate:Int,writingDays:Int,latestDayOfWriting:String): WritingFragment {
        val args = Bundle()
        args.putInt("rate", rate)
        args.putInt("writingDays", writingDays)
        args.putString("latestDayOfWriting", latestDayOfWriting)
        val fragment = WritingFragment()
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
        binding = FragmentWritingBinding.inflate(inflater,container,false)
        val readingRate =arguments?.getInt("rate")!!
        val readingDays = arguments?.getInt("writingDays")!!
        val latestDayOfReading = arguments?.getString("latestDayOfWriting").toString()
        setViews(readingRate,readingDays,latestDayOfReading)
        return binding.root
    }

    @SuppressLint("SetTextI18n")
    fun setViews(rate:Int, readingDays:Int, latestDayOfReading:String){
        binding.writingRate.text = "Writing Rate : $rate%"
        binding.level.text = "Level : ${getTheLevelName(rate)}"
        binding.latestDayOfWriting.text = "Latest Day Of Writing  : $latestDayOfReading"
        binding.writingDays.text = "$readingDays days of Writing"
    }



    private fun getTheLevelName(rate:Int):String{
        return when(rate){
            in 0..20 -> "Bad"
            in 21..40 -> "Normal"
            in 41..60 -> "Good"
            in 61..80 -> "Very Good"
            else -> "Excellent"
        }
    }

}