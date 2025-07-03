package com.example.possible.util.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.net.toUri
import androidx.recyclerview.widget.RecyclerView
import com.example.possible.databinding.SelectedChildItemBinding
import com.example.possible.model.Child

class SelectingAdapter(private val data: ArrayList<Child>) :
    RecyclerView.Adapter<SelectingAdapter.ChildHolder>() {
    // Create ViewHolder class
    class ChildHolder(val binding: SelectedChildItemBinding) : RecyclerView.ViewHolder(binding.root)
     private var selectedItems = ArrayList<String>()
    // Create ViewHolder and inflate the item layout
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ChildHolder {
        val binding =
            SelectedChildItemBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return ChildHolder(binding)
    }
    fun getSelectedItems(): ArrayList<String> {
        return selectedItems
    }

    // Bind data to the ViewHolder
    override fun onBindViewHolder(holder: ChildHolder, position: Int) {

        holder.binding.name.text = data[position].name
        holder.binding.profileImage.setImageURI(data[position].imageUri.toUri())
        holder.binding.select.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                selectedItems.add(data[position].id.toString())
            } else {
                selectedItems.remove(data[position].id.toString())
            }
    }
        }

    // Return the size of the data list
    override fun getItemCount(): Int {
        return data.size
    }
}