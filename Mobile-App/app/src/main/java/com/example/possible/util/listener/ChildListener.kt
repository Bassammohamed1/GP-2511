package com.example.possible.util.listener

import com.example.possible.model.Child

interface ChildListener {
    fun onClick(child: Child)
    fun onDelete(position: Int, child: Child)
}