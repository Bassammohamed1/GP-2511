package com.example.possible.repo.local.database.dao

import androidx.room.Dao
import androidx.room.Query
import com.example.possible.model.Child

import androidx.room.*
import com.example.possible.model.SolvedTest
import com.example.possible.model.Test

@Dao
interface ChildDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertChild(child: Child)

    @Query("SELECT * FROM children")
    suspend fun getAllChildren(): List<Child>
    @Query("SELECT * FROM children WHERE id = :id")
    suspend fun getChildById(id: Int): Child?

    @Delete
    suspend fun deleteChild(child: Child)

    @Update
    suspend fun editChild(child: Child)

    @Query("DELETE FROM children")
    suspend fun deleteAllChildren()



    //Report Queries


    //rates update
    @Query("UPDATE children SET readingRate = :readingRate WHERE id = :childId")
    suspend fun updateReadingRate(childId: Int, readingRate: Int)
    @Query("UPDATE children SET writingRate = :writingRate WHERE id = :childId")
    suspend fun updateWritingRate(childId: Int, writingRate: Int)

    //days update
    @Query("UPDATE children SET readingDays = :readingDays WHERE id = :childId")
    suspend fun updateReadingDays(childId: Int, readingDays: Int)
    @Query("UPDATE children SET writingDays = :writingDays WHERE id = :childId")
    suspend fun updateWritingDays(childId: Int, writingDays: Int)

    //latest update
    @Query("UPDATE children SET latestReadingDay = :latestReadingDay WHERE id = :childId")
    suspend fun updateLatestReadingDay(childId: Int, latestReadingDay: String)
    @Query("UPDATE children SET latestWritingDay = :latestWritingDay WHERE id = :childId")
    suspend fun updateLatestWritingDay(childId: Int, latestWritingDay: String)

    //tests update
    @Query("UPDATE children SET childTests = :childTests WHERE id = :childId")
    suspend fun updateChildTests(childId: Int, childTests: List<Test>)

    @Query("UPDATE children SET childSolvedTests = :solvedTests WHERE id = :childId")
    suspend fun updateSolvedTests(childId: Int, solvedTests: List<SolvedTest>)


}
