package com.example.possible.util

import android.content.Context
import com.example.possible.repo.local.SharedPref

object LogoutHandler {
    var isLoggingOUt = false

    fun clearAllLoggedData(con:Context){
        //setUp prefs
        val pref=SharedPref(con)
        pref.resetPrefs()
    }

}