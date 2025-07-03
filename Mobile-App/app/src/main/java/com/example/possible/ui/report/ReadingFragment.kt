package com.example.possible.ui.report

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.example.possible.databinding.FragmentReadingBinding

class ReadingFragment : Fragment() {
   private lateinit var binding: FragmentReadingBinding
   fun newInstance(rate:Int,readingDays:Int,latestDayOfReading:String): ReadingFragment {
        val args = Bundle()
       args.putInt("rate", rate)
       args.putInt("readingDays", readingDays)
       args.putString("latestDayOfReading", latestDayOfReading)
       val fragment = ReadingFragment()
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
        binding = FragmentReadingBinding.inflate(inflater,container,false)
        val readingRate =arguments?.getInt("rate")!!
        val readingDays = arguments?.getInt("readingDays")!!
        val latestDayOfReading = arguments?.getString("latestDayOfReading").toString()
        setViews(readingRate,readingDays,latestDayOfReading)
        return binding.root
    }

    @SuppressLint("SetTextI18n")
    fun setViews(rate:Int, readingDays:Int, latestDayOfReading:String){
        binding.readingRate.text = "Reading Rate : $rate%"
        binding.level.text = "Level : ${getTheLevelName(rate)}"
        binding.latestDayOfReading.text = "Latest Day Of Reading  : $latestDayOfReading"
        binding.readingDays.text = "$readingDays days of reading"
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