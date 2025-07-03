package com.example.possible.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "test")
data class Test(
    @PrimaryKey(autoGenerate = false)
    val name: String,
    val type: String,
    var listOfQuestions: List<Question>,
    val childrenId: List<String>
)
data class Question (
    val type: String,
    val question:String,
    val level:String= "Beginner",
)