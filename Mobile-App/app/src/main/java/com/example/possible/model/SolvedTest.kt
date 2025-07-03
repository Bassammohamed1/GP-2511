package com.example.possible.model

data class SolvedTest(
    val testName:String,
    val testType:String,
    val q1Points:Int,
    val q2Points:Int,
    val q3Points:Int,
    val q4Points:Int,
    val totalPoints:Int,
    val date:String
)
