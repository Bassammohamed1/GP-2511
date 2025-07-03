package com.example.possible.repo.local.converters

    import androidx.room.TypeConverter
    import com.example.possible.model.Test
    import com.example.possible.model.SolvedTest
    import com.google.gson.Gson
    import com.google.gson.reflect.TypeToken

class ChildConverters {

        private val gson = Gson()
        @TypeConverter
        fun fromTestList(value: List<Test>?): String {
            return gson.toJson(value)
        }
        @TypeConverter
        fun toTestList(value: String): List<Test>? {
            val listType = object : TypeToken<List<Test>>() {}.type
            return gson.fromJson(value, listType)
        }
        @TypeConverter
        fun fromSolvedTestList(value: List<SolvedTest>?): String {
            return gson.toJson(value)
        }
        @TypeConverter
        fun toSolvedTestList(value: String): List<SolvedTest>? {
            val listType = object : TypeToken<List<SolvedTest>>() {}.type
            return gson.fromJson(value, listType)
        }
    }

