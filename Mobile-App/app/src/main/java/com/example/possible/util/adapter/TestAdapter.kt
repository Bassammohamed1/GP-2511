package com.example.possible.util.adapter

import android.annotation.SuppressLint
import android.view.LayoutInflater
import android.view.View.GONE
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.example.possible.R
import com.example.possible.databinding.TestItemBinding
import com.example.possible.model.Test
import com.example.possible.util.listener.TestListener

class TestAdapter(private val data: ArrayList<Test>,val listener: TestListener) :
    RecyclerView.Adapter<TestAdapter.TestHolder>() {
       private var toDoMode = false

    // Create ViewHolder class
    class TestHolder(val binding: TestItemBinding) : RecyclerView.ViewHolder(binding.root)

    // Create ViewHolder and inflate the item layout
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): TestHolder {
        val binding = TestItemBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return TestHolder(binding)
    }

    @SuppressLint("NotifyDataSetChanged")
    fun toDoMode(){
      toDoMode = true
      notifyDataSetChanged()
    }

    // Bind data to the ViewHolder
    @SuppressLint("SetTextI18n", "ResourceAsColor")
    override fun onBindViewHolder(holder: TestHolder, position: Int) {
        if(toDoMode){
            holder.binding.deleteBtn.visibility = GONE
        }
        val testType = data[position].type
        val context = holder.binding.root.context  // علشان تجيب الكونتكست

        when (testType) {
            "Dyscalculia" -> {
                holder.binding.testId.text = "Cal"
                holder.binding.testId.setTextColor(ContextCompat.getColor(context, R.color.cal))
            }
            "Dyslexia" -> {
                holder.binding.testId.text = "Dys"
                holder.binding.testId.setTextColor(ContextCompat.getColor(context, R.color.des))
            }
            "Dysgraphia" -> {
                holder.binding.testId.text = "Gra"
                holder.binding.testId.setTextColor(ContextCompat.getColor(context, R.color.gra))
            }
        }

        holder.binding.testName.text = data[position].name
        holder.binding.root.setOnClickListener{
            listener.onTestClick(data[position])
        }
        holder.binding.deleteBtn.setOnClickListener {
            listener.onDeleteClick(data[position],position)
        }
    }

    // Return the size of the data list
    override fun getItemCount(): Int {
        return data.size
    }
}