package com.example.possible.repo.local.converters

import androidx.room.TypeConverter
import com.example.possible.model.Question
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

class Converters {

    private val gson = Gson()

    // لتحويل الـ List<Question> إلى String
    @TypeConverter
    fun fromQuestionList(value: List<Question>): String {
        return gson.toJson(value)
    }

    // لتحويل الـ String إلى List<Question>
    @TypeConverter
    fun toQuestionList(value: String): List<Question> {
        val type = object : TypeToken<List<Question>>() {}.type
        return gson.fromJson(value, type)
    }

    // لتحويل الـ List<String> إلى String
    @TypeConverter
    fun fromStringList(value: List<String>): String {
        return gson.toJson(value)
    }

    // لتحويل الـ String إلى List<String>
    @TypeConverter
    fun toStringList(value: String): List<String> {
        val type = object : TypeToken<List<String>>() {}.type
        return gson.fromJson(value, type)
    }
}
