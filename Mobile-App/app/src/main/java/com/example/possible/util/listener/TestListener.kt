package com.example.possible.util.listener

import com.example.possible.model.SolvedTest
import com.example.possible.model.Test

interface TestListener {
    fun onTestClick(test: Test)
    fun onDeleteClick(test: Test, position: Int)
    fun onSolvedClick(test: SolvedTest, position: Int)
    fun onSolvedDelete(test: SolvedTest, position: Int)

}