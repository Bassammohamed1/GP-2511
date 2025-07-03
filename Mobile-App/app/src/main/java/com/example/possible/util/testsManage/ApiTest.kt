package com.example.possible.util.testsManage

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity
data class ApiTest(
    @PrimaryKey(autoGenerate = false)
    val testName: String,
    val testCategory: String,
    val questionsNo: String,
    val questions: List<TestQuestionForApi>,
    val childrenId: List<String>

)

