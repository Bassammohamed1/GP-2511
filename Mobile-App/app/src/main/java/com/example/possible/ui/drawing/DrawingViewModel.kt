package com.example.possible.ui.drawing

import android.content.Context
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.possible.model.Child
import com.example.possible.model.UpdatedValue
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.repo.remote.RetrofitBuilder
import com.example.possible.util.helper.ChildTraker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DrawingViewModel:ViewModel() {




    fun updateWritingRate(context: Context, pref: SharedPref,newRate:Int,db: LocalRepoImp,points:Int) {
        val id = ChildTraker.getChildId()
        viewModelScope.launch {
            val child = db.getChildById(ChildTraker.getChildId())
            val latestSelecting = child.latestWritingDay
            ChildTraker.setWritingRateOfTries(points)
            withContext(Dispatchers.Main){
            }
            //get the new rate and assign it
            val newWritingRate = ChildTraker.getWritingRate()
            //update the rate
            db.updateWritingRate(ChildTraker.getChildId(), newWritingRate)

            //update the writing days and latest writing day
            if (ChildTraker.isAnotherDay(latestSelecting)){
                db.updateWritingDays(ChildTraker.getChildId(),child.writingDays+1)
                db.updateLatestWritingDay(ChildTraker.getChildId(),ChildTraker.getCurrentDate())
                val tasks = listOf(
                    async { sendWritingRateToApi(context,pref,newRate,id) },
                    async { sendWritingDaysToApi(context,pref,child.writingDays+1,id) },
                    async { sendLatestWritingDayToApi(context,pref, ChildTraker.getCurrentDate(),id) }
                )
                tasks.awaitAll()
            }
            else{
                sendWritingRateToApi(context,pref,newRate,id)
            }

        }
    }

    private suspend fun sendWritingRateToApi(context: Context, pref: SharedPref, rate:Int, id:Int){
        val op = "replace"
        val path = "WritingRate"
        val token = "Bearer ${pref.getToken()}"
        val response = RetrofitBuilder.updatedValue.updateNewValue(
            token,
            id.toString(),
            listOf(UpdatedValue(op,path,rate))
        )
        if(response.isSuccessful){
            Toast.makeText(context, "RateUpdated", Toast.LENGTH_SHORT).show()
        }
        else{
            Toast.makeText(context, "RateFailed", Toast.LENGTH_SHORT).show()
        }
    }

    private suspend fun sendWritingDaysToApi(context: Context, pref: SharedPref, days:Int, id:Int){
        val op = "replace"
        val path = "WritingDays"
        val token = "Bearer ${pref.getToken()}"
        val response = RetrofitBuilder.updatedValue.updateNewValue(
            token,
            id.toString(),
            listOf( UpdatedValue(op,path,days))
        )
        if(response.isSuccessful){
            Toast.makeText(context, "DaysUpdated", Toast.LENGTH_SHORT).show()
        }
        else{
            Toast.makeText(context, "DaysFailed", Toast.LENGTH_SHORT).show()
        }
    }

    private suspend fun sendLatestWritingDayToApi(context: Context, pref: SharedPref, lastDay:String, id:Int){
        val op = "replace"
        val path = "LastWritingTime"
        val token = "Bearer ${pref.getToken()}"
        val response = RetrofitBuilder.updatedValue.updateNewValue(
            token,
            id.toString(),
            listOf( UpdatedValue(op,path,lastDay))
        )
        if(response.isSuccessful){
            Toast.makeText(context, "DayUpdated", Toast.LENGTH_SHORT).show()
        }
        else{
            Toast.makeText(context, "DayFailed", Toast.LENGTH_SHORT).show()
        }
    }

}


