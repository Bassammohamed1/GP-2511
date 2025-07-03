package com.example.possible.util.helper
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlin.math.roundToInt

object ChildTraker {
    private var readingRate: Float = 0f
    private var writingRate: Float = 0f
    private var childId: Int = 0


    fun setChildId(id: Int) {
        childId = id
    }

    fun getChildId(): Int {
        return childId
    }


    fun getReadingRate(): Int {
        val rate = readingRate.roundToInt()
        return rate
    }

    fun getWritingRate(): Int {

        return writingRate.roundToInt()
    }

    fun setReadingRate(correct: Float, count: Float) {
        if (readingRate == 0f)  {
            readingRate = (correct / count) * 100
        }
        else {
            val newRate = (correct / count) * 100
            readingRate = (newRate + readingRate) / 2
        }
    }
    fun setReadingRate(rate: Int) {
        readingRate = rate.toFloat()
    }

    fun setWritingRateOfTries(points: Int) {
        if (writingRate == 0f)  {
            writingRate = points.toFloat()
        }
        else {
            val newRate = points.toFloat()
            writingRate = (newRate + writingRate) / 2
        }
    }
    fun setWritingRate(rate: Int) {
        writingRate = rate.toFloat()
    }


    fun isAnotherDay(latestData: String?): Boolean {
        if (latestData == null) return true
        return latestData != getCurrentDate()
    }
     fun getCurrentDate(): String {
        val currentDate = LocalDateTime.now()
        val formattedDate = currentDate.format(DateTimeFormatter.ofPattern("dd/MM/yyyy"))
        return formattedDate
    }
}


