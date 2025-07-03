package com.example.possible.util.adapter

import android.annotation.SuppressLint
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.text.isDigitsOnly
import androidx.recyclerview.widget.RecyclerView
import com.example.possible.databinding.ResultBoxBinding

class ResultAdapter(private val data: ArrayList<Int>) :
    RecyclerView.Adapter<ResultAdapter.Rholder>() {

    // ViewHolder class
    class Rholder(val binding: ResultBoxBinding) : RecyclerView.ViewHolder(binding.root)

    // Create ViewHolder and inflate the item layout
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Rholder {
        val binding = ResultBoxBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return Rholder(binding)
    }

    // Bind data to the ViewHolder
    override fun onBindViewHolder(holder: Rholder, @SuppressLint("RecyclerView") position: Int) {
        // عرض القيمة الحالية في EditText
        //holder.binding.eTRes.setText(data[position].toString())

        // استماع للتغيرات في EditText
        holder.binding.eTRes.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}

            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                if (s.toString().isNotEmpty()) {
                    // تحديث القيمة في القائمة الرئيسية
                    data[position] = s.toString().toInt()
                }
            }

            override fun afterTextChanged(s: Editable?) {}
        })
    }

    // Return the size of the data list
    override fun getItemCount(): Int {
        return data.size
    }
}
