package com.example.possible.util.adapter

import android.annotation.SuppressLint
import android.content.Context
import android.net.Uri
import android.provider.MediaStore
import android.util.Log
import android.view.LayoutInflater
import android.view.View.GONE
import android.view.View.VISIBLE
import android.view.ViewGroup
import androidx.core.net.toUri
import androidx.recyclerview.widget.RecyclerView
import com.bumptech.glide.Glide
import com.example.possible.R
import com.example.possible.databinding.ChildCardBinding
import com.example.possible.model.Child
import com.example.possible.repo.local.SharedPref
import com.example.possible.util.helper.dataManager.AppDataManager
import com.example.possible.util.listener.ChildListener
import java.io.File

class ChildrenAdapter(private var data: ArrayList<Child>, private val listener: ChildListener ,private val pref: SharedPref) :
    RecyclerView.Adapter<ChildrenAdapter.ChildHolder>() {

    // Create ViewHolder class
    class ChildHolder(val binding: ChildCardBinding) : RecyclerView.ViewHolder(binding.root)
    private  var testsMode=false
    private var viewMode=false

    @SuppressLint("NotifyDataSetChanged")
    fun setViewMode(mode: Boolean) {
        viewMode = mode
        notifyDataSetChanged()
    }



    @SuppressLint("NotifyDataSetChanged")
    fun setTestMode(mode: Boolean) {
        testsMode = mode
        notifyDataSetChanged()
    }

    fun onDelete(position: Int, newList: ArrayList<Child>) {
        data.removeAt(position)
        notifyItemRemoved(position)

        data.clear()
        data.addAll(newList)

        notifyItemRangeChanged(position, data.size)
    }


    @SuppressLint("NotifyDataSetChanged")
    fun updateData(newList: ArrayList<Child>) {
        data = newList
        notifyDataSetChanged()
    }

    // Create ViewHolder and inflate the item layout
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ChildHolder {
        val binding = ChildCardBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return ChildHolder(binding)
    }

    // Bind data to the ViewHolder
    @SuppressLint("SetTextI18n")
    override fun onBindViewHolder(holder: ChildHolder, position: Int) {
        if (testsMode) {
            holder.binding.deleteBtn.visibility = GONE
            holder.binding.testIcon.visibility = VISIBLE
        }


        if (viewMode) {
            holder.binding.deleteBtn.visibility = GONE
            holder.binding.testIcon.visibility = GONE
        }

        val child = data[position]

        // Set the name text
        holder.binding.name.text =child.name


        val toDoTests = child.childTests.size - child.childSolvedTests.size
        // Set the test icon text
        if (testsMode&&toDoTests != 0) {
            holder.binding.testIcon.visibility = VISIBLE
            holder.binding.testIcon.text = toDoTests.toString()
        } else {
            holder.binding.testIcon.visibility = GONE
        }

        // Set click listeners
        holder.binding.root.setOnClickListener {
            listener.onClick(child)
        }
        holder.binding.deleteBtn.setOnClickListener {
            listener.onDelete(position, child)
        }
        if(pref.getRole()=="Specialist"){
            holder.binding.deleteBtn.visibility=GONE
        }



        // Log the URI for debugging
        Log.d("ChildrenAdapter", "Image URI: ${child.imageUri}")


        // Load the image using Glide
        Glide.with(holder.itemView.context)
            .load((child.imageUri).toUri())
            .placeholder(R.color.white)
            .error(R.drawable.error_signal)
            .into(holder.binding.profileImage)
    }


        // Return the size of the data list
    override fun getItemCount(): Int {
        return data.size
    }
}





