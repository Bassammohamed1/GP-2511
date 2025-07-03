package com.example.possible.model

import androidx.room.Entity
import androidx.room.PrimaryKey


@Entity(tableName = "children")
data class Child(
    @PrimaryKey(autoGenerate = false)
    val id:Int,
    val name: String,
    val age: Int,
    val imageUri: String,
    val gender: Int,
    val difficulty: String,
    val readingRate: Int,
    val writingRate: Int,
    val readingDays :Int,
    val writingDays :Int,
    val latestReadingDay:String?,
    val latestWritingDay:String?,
    val date:String,
    val childTests:List<Test>,
    val childSolvedTests:List<SolvedTest>
)