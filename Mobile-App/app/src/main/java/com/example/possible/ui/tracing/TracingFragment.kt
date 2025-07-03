package com.example.possible.ui.tracing

import android.annotation.SuppressLint
import android.graphics.Path
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.example.possible.databinding.FragmentTracingBinding
import com.example.possible.repo.local.LettersAndNumbers
import com.example.possible.repo.local.TracingPaths

class TracingFragment : Fragment() {
    private lateinit var binding: FragmentTracingBinding

    private var pathsSize: Int = 0
    private var completedPaths:Int=0
    private lateinit var paths:ArrayList<Path>


    fun getInstance(index:Int,type:String): TracingFragment {
        val fragment = TracingFragment()
        val args = Bundle()
         args.putInt("index",index)
        args.putString("type",type)
        fragment.arguments = args
        return fragment
    }

    @SuppressLint("ClickableViewAccessibility")
    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {

        binding = FragmentTracingBinding.inflate(inflater, container, false)

        val index=arguments?.getInt("index")!!
        val type=arguments?.getString("type")
        paths = when(type){
           "letter"->{
               TracingPaths.getLetterPaths(index)
           }
            else->{
                TracingPaths.getNumberPaths(index)
            }
        }
        val tracingName: String = when(type){
          "letter"->{
              LettersAndNumbers.letters[index].name
          }
          else->{
              LettersAndNumbers.numbers[index].name}
      }
        binding.TracingView.setNewPathArray(paths,tracingName)

       binding.letterName.text = tracingName

        return binding.root
    }
    fun getResult():Pair<Int,Int>{
        pathsSize=binding.TracingView.pathArray.size
        completedPaths=binding.TracingView.completedPaths.size
        return Pair(pathsSize,completedPaths)
    }
    fun getResultsForTest():Int{
        val pathsSize=binding.TracingView.pathArray.size
        val completedPaths=binding.TracingView.completedPaths.size
        val points= pathsSize-completedPaths
        val result = if(points == 0){
            2
        }
        else if((pathsSize.toFloat()/points.toFloat()).toInt() >=2){
            1
        }
        else{
            0
    }
        return result
    }



}