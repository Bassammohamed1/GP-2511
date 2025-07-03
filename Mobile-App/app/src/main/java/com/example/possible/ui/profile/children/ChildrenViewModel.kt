package com.example.possible.ui.profile.children

import android.annotation.SuppressLint
import android.content.Context
import android.util.Log
import android.widget.Toast
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.possible.model.AllChildrenChildModel
import com.example.possible.model.Child
import com.example.possible.model.RemoteChild
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.repo.remote.RetrofitBuilder
import com.example.possible.util.helper.InterNetHelper
import com.example.possible.util.helper.dataManager.AppDataManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

class ChildrenViewModel :ViewModel(){

    private var _children : MutableLiveData<List<Child>> = MutableLiveData()
    val children : MutableLiveData<List<Child>> = _children

    fun deleteChild(onStart : () -> Unit,id:Int ,onFinish: () -> Unit,db: LocalRepoImp,pref: SharedPref){
        deleteFromRemote(id,onStart,onFinish,db,pref)
    }

    private fun deleteFromLocal(id:Int,onFinish: () -> Unit,db:LocalRepoImp){
        viewModelScope.launch {
            val c= db.getChildById(id)
            db.deleteChild(child =c)
            withContext(Dispatchers.Main){
                onFinish()
            }
        }
    }

    private fun deleteFromRemote(id:Int, onStart: () -> Unit, onFinish: () -> Unit, db:LocalRepoImp, pref: SharedPref){
        onStart()
        viewModelScope.launch {
            try {
                val key = "Bearer ${pref.getToken()}"
                val response = RetrofitBuilder.deleteChildApiService.deleteChild(key,id)
                if (response.isSuccessful && response.body()?.statusCode == 200) {
                    deleteFromLocal(id, onFinish = onFinish, db)
                } else {
                    withContext(Dispatchers.Main) { onFinish()
                        Log.d("DeleteChildViewModel", "Error: ")}

                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { onFinish()}
                Log.d("DeleteChildViewModel", "Error: ")}
            }
        }


     @SuppressLint("SuspiciousIndentation")
     fun getUserChildrenFromApi(onStart: () -> Unit, context: Context, db:LocalRepoImp, pref: SharedPref, onFinish: () -> Unit){
         if(!InterNetHelper.isInternetAvailable(context)){
             Toast.makeText(context, "Check your internet connection", Toast.LENGTH_SHORT).show()
             return
         }
         onStart()
         viewModelScope.launch(Dispatchers.IO){
            try {

            val token = "Bearer ${pref.getToken()}"
                Log.i("TOkENII",token)
            val response = RetrofitBuilder.getUserChildrenApiService.getUserChildren(token)
            if (response.isSuccessful) {
                storeUserChildrenIntoRoom(response.body()!!,db,context ,onFinish)

            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
                onFinish()
            }
          }
        }
    }
    fun getAllChildrenFromApi(onStart: () -> Unit,context: Context,db:LocalRepoImp,pref: SharedPref,onFinish: () -> Unit){
        if(!InterNetHelper.isInternetAvailable(context)){
            Toast.makeText(context, "Check your internet connection", Toast.LENGTH_SHORT).show()
            return
        }
        onStart()
        viewModelScope.launch(Dispatchers.IO){
            try {val token = "Bearer ${pref.getToken()}"
            val response = RetrofitBuilder.getAllChildrenApiService.getAllChildren(token)
            if (response.isSuccessful) {
                storeAllChildrenIntoRoom(response.body()!!,db,context,onFinish )

            }} catch (e: Exception) {
            withContext(Dispatchers.Main) {
                Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
                onFinish() }

        }}
    }
    private fun storeAllChildrenIntoRoom(children: List<AllChildrenChildModel>, db:LocalRepoImp, context: Context,onFinish: () -> Unit){
        viewModelScope.launch(Dispatchers.IO) {
            for (child in children) {
                val age =child.age
                val name = child.name
                val id = child.id
                val diff = child.difficult
                val readingRate = child.readingRate
                val writingRate = child.writingRate
                val lastReadingTime = child.lastReadingTime
                val lastWritingTime = child.lastWritingTime
                val readingDays = child.readingDays
                val writingDays = child.writingDays
                val imageUri = AppDataManager.downloadAndSaveChildImage(context, child.image,"${child.name}_${child.id}")
                val localChild = Child(
                    id, name, age, imageUri.toString(),child.gender,
                    diff,readingRate,writingRate,readingDays,writingDays,lastReadingTime,lastWritingTime,returnDate(),
                    emptyList(),emptyList()
                )
                db.insertChild(localChild)
            }
            getChildren(db)
            withContext(Dispatchers.Main) {
                onFinish()
            }
        }
    }



     @SuppressLint("SuspiciousIndentation")
     private fun storeUserChildrenIntoRoom(children: List<RemoteChild>, db:LocalRepoImp, context: Context, onFinish: () -> Unit){
        viewModelScope.launch(Dispatchers.IO) {
            for (child in children) {
                val age =child.age
                val name = child.name
                val id = child.id
                val readingRate = child.readingRate
                val writingRate = child.writingRate
                val lastReadingTime = child.lastReadingTime
                val lastWritingTime = child.lastWritingTime
                val readingDays = child.readingDays
                val writingDays = child.writingDays
                val diff = child.difficult
                val imageUri = AppDataManager.downloadAndSaveChildImage(context, child.image,"${child.name}_${child.id}")
                val localChild = Child(
                    id, name, age, imageUri.toString(),child.gender,
                    diff,readingRate,writingRate,readingDays,writingDays,lastReadingTime,lastWritingTime,returnDate(),
                    emptyList(),emptyList())
                    db.insertChild(localChild)
            }
             getChildren(db)
            withContext(Dispatchers.Main) {
                onFinish()
            }
        }
    }
    fun getChildren(db:LocalRepoImp){
        viewModelScope.launch (Dispatchers.IO){
            val children = db.getAllChildren()
            withContext(Dispatchers.Main){
                _children.value = children
            }

        }
    }
    private fun deleteAllChildren(db:LocalRepoImp){
        viewModelScope.launch (Dispatchers.IO){
            db.deleteAllChildren()
            getChildren(db)
        }

    }

    private fun returnDate(): String {
        val currentDate = LocalDateTime.now()
        return currentDate.format(DateTimeFormatter.ofPattern("dd/MM/yyyy"))
    }

}