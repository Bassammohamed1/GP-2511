package com.example.possible.util.adapter

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.example.possible.R
import com.example.possible.databinding.ChosenTextCardBinding
import com.example.possible.util.listener.TextListener

class TextsAdapter(private val data: ArrayList<String>, private val listener: TextListener) :
    RecyclerView.Adapter<TextsAdapter.Tholder>() {

    // Create ViewHolder class
    class Tholder(val binding: ChosenTextCardBinding) : RecyclerView.ViewHolder(binding.root)

    // Create ViewHolder and inflate the item layout
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Tholder {
        val binding = ChosenTextCardBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return Tholder(binding)
    }
    private fun getRondomColor(textView: TextView){
        val listOfColors = listOf(1,2,3,4,5)
        val randomColor = listOfColors.random()
        when(randomColor) {
            1 -> textView.setTextColor(ContextCompat.getColor(textView.context, R.color.cal))
            2 -> textView.setTextColor(ContextCompat.getColor(textView.context, R.color.des))
            3 -> textView.setTextColor(ContextCompat.getColor(textView.context, R.color.gra))
            4 -> textView.setTextColor(ContextCompat.getColor(textView.context, R.color.white))
            5 -> textView.setTextColor(ContextCompat.getColor(textView.context, R.color.error))
        }

    }

    // Bind data to the ViewHolder
    override fun onBindViewHolder(holder: Tholder, position: Int) {
       holder.binding.text.text = data[position]
        getRondomColor(holder.binding.text)
        holder.binding.root.setOnClickListener{
            listener.onClick(data[position])
        }
    }

    // Return the size of the data list
    override fun getItemCount(): Int {
        return data.size
    }
}