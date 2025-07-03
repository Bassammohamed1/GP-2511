package com.example.possible.repo.local.database

import androidx.room.Database
import com.example.possible.model.Child
import com.example.possible.repo.local.database.dao.ChildDao

import android.content.Context
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.example.possible.model.Test
import com.example.possible.repo.local.converters.ChildConverters
import com.example.possible.repo.local.database.dao.TestDao
import com.example.possible.repo.local.converters.Converters

@Database(entities = [Child::class,Test::class], version = 1, exportSchema = false)
@TypeConverters(Converters::class, ChildConverters::class)

abstract class AppDatabase : RoomDatabase() {
    abstract fun childDao(): ChildDao
    abstract fun testDao(): TestDao

    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getDatabase(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "child_database"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}
