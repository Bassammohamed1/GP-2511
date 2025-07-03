package com.example.possible.ui.reading

import android.content.Context
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.possible.model.UpdatedValue
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.repo.remote.RetrofitBuilder
import com.example.possible.util.helper.ChildTraker
import com.example.possible.util.helper.InterNetHelper
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch

class ReadingViewModel : ViewModel() {
    fun updateReadingRate(context: Context,pref: SharedPref,correctWords:Int,totalWords:Int,db: LocalRepoImp) {
        ChildTraker.setReadingRate(correctWords.toFloat(),totalWords.toFloat())
        val newRate = ChildTraker.getReadingRate()
        val id = ChildTraker.getChildId()

        viewModelScope.launch {
            db.updateReadingRate(id,newRate)
            val child = db.getChildById(id)


            if(ChildTraker.isAnotherDay(child.latestReadingDay)){
                db.updateReadingDays(id, child.readingDays + 1)
                db.updateLatestReadingDay(id, ChildTraker.getCurrentDate())
                if(InterNetHelper.isInternetAvailable(context)){


             val tasks = listOf(
                async { sendReadingRateToApi(context,pref,newRate,id) },
                async { sendReadingDaysToApi(context,pref,child.readingDays+1,id) },
                async { sendLatestReadingDayToApi(context,pref,ChildTraker.getCurrentDate(),id) }
            )
            tasks.awaitAll()
                }
                else{
                    Toast.makeText(context, "No Internet Connection", Toast.LENGTH_SHORT).show()
                    return@launch
                }
            }
            else{
                if(InterNetHelper.isInternetAvailable(context)){
                sendReadingRateToApi(context,pref,newRate,id)}
                else{
                    Toast.makeText(context, "No Internet Connection", Toast.LENGTH_SHORT).show()
                    return@launch
                }
            }
        }
    }

    private suspend fun sendReadingRateToApi(context: Context, pref: SharedPref, rate:Int, id:Int){
        val op = "replace"
        val path = "ReadingRate"
        val token = "Bearer ${pref.getToken()}"
        val response = RetrofitBuilder.updatedValue.updateNewValue(
            token,
            id.toString(),
            listOf(UpdatedValue(op,path,rate))
        )
        if(response.isSuccessful){
            //Toast.makeText(context, "RateUpdated", Toast.LENGTH_SHORT).show()
        }
        else{
            Toast.makeText(context, "RateFailed", Toast.LENGTH_SHORT).show()
        }
    }

    private suspend fun sendReadingDaysToApi(context: Context, pref: SharedPref, days:Int, id:Int){
        val op = "replace"
        val path = "ReadingDays"
        val token = "Bearer ${pref.getToken()}"
        val response = RetrofitBuilder.updatedValue.updateNewValue(
            token,
            id.toString(),
            listOf( UpdatedValue(op,path,days))
        )
        if(response.isSuccessful){
           // Toast.makeText(context, "DaysUpdated", Toast.LENGTH_SHORT).show()
        }
        else{
            Toast.makeText(context, "DaysFailed", Toast.LENGTH_SHORT).show()
        }
    }

    private suspend fun sendLatestReadingDayToApi(context: Context, pref: SharedPref, lastDay:String, id:Int){
        val op = "replace"
        val path = "lastReadingTime"
        val token = "Bearer ${pref.getToken()}"
        val response = RetrofitBuilder.updatedValue.updateNewValue(
            token,
            id.toString(),
            listOf( UpdatedValue(op,path,lastDay))
        )
        if(response.isSuccessful){
            //Toast.makeText(context, "DayUpdated", Toast.LENGTH_SHORT).show()
        }
        else{
            Toast.makeText(context, "DayFailed", Toast.LENGTH_SHORT).show()
        }
    }
}
