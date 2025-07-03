package com.example.possible.repo.local.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.example.possible.model.Test

@Dao
interface TestDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertTest(test: Test)

    @Query("SELECT * FROM test")
    suspend fun getAllTests(): List<Test>

    @Query("SELECT * FROM test WHERE name = :name")
    suspend fun getTestByName(name: String): Test?

    @Delete
    suspend fun deleteTest(test: Test)

}