package com.example.possible.util.adapter

import android.annotation.SuppressLint
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.example.possible.R
import com.example.possible.databinding.TestItemBinding
import com.example.possible.model.SolvedTest
import com.example.possible.util.listener.TestListener

class SolvedTestAdapter(private val data: ArrayList<SolvedTest>,private val listener: TestListener) :
    RecyclerView.Adapter<SolvedTestAdapter.TestItemHolder>() {

    // Create ViewHolder class
    class TestItemHolder(val binding: TestItemBinding) : RecyclerView.ViewHolder(binding.root)

    // Create ViewHolder and inflate the item layout
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): TestItemHolder {
        val binding = TestItemBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return TestItemHolder(binding)
    }

    // Bind data to the ViewHolder
    @SuppressLint("SetTextI18n", "ResourceAsColor")
    override fun onBindViewHolder(holder: TestItemHolder, position: Int) {
        holder.binding.testName.text = data[position].testName
        holder.binding.testId.text = (position+1).toString()
        holder.binding.root.setOnClickListener{
            listener.onSolvedClick(data[position],position)
        }
        val testType = data[position].testType
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
        holder.binding.deleteBtn.setOnClickListener {
            listener.onSolvedDelete(data[position],position)
    }
    }

    // Return the size of the data list
    override fun getItemCount(): Int {
        return data.size
    }
}