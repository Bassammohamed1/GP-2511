package com.example.possible.repo.local

import android.content.Context
import com.example.possible.model.User

class SharedPref(context: Context) {

    //
    private val useCounterPref=context.getSharedPreferences("count",Context.MODE_PRIVATE)


    private val sharedPref=context.getSharedPreferences("mode",Context.MODE_PRIVATE)
    private val profilePref=context.getSharedPreferences("profile",Context.MODE_PRIVATE)
    private val appPathPref=context.getSharedPreferences("path",Context.MODE_PRIVATE)
    private val testPref=context.getSharedPreferences("test",Context.MODE_PRIVATE)
    private val ipPref=context.getSharedPreferences("ip",Context.MODE_PRIVATE)



    fun setProfileData(name:String, email:String, password:String,token:String,userId:String,expiration:String,imagePath:String,role:String){
        profilePref.edit().putString("name",name).apply()
        profilePref.edit().putString("email",email).apply()
        profilePref.edit().putString("imagePath",imagePath).apply()
        profilePref.edit().putString("password",password).apply()
        profilePref.edit().putString("token",token).apply()
        profilePref.edit().putString("userId",userId).apply()
        profilePref.edit().putString("expiration",expiration).apply()
        profilePref.edit().putString("role",role).apply()
    }
    fun getToken():String?{
        return profilePref.getString("token","")
    }
    fun setRole(role:String){
        profilePref.edit().putString("role",role).apply()
    }
    fun getRole():String?{
        return profilePref.getString("role","")
    }
    fun getProfileDetails(): User {
        return User(
            profilePref.getString("name","")!!,
            profilePref.getString("imagePath","")!!,
            profilePref.getString("email","")!!,
            profilePref.getString("password","")!!,
            profilePref.getString("token","")!!,
            profilePref.getString("userId","")!!,
            profilePref.getString("expiration","")!!,
            profilePref.getString("role","")!!
        )

    }
    fun setMode(mode:String){
        sharedPref.edit().putString("mode",mode).apply()
    }
    fun getMode():String?{
        return sharedPref.getString("mode","beginner")
    }
    fun setToken(token:String){
        profilePref.edit().putString("token",token).apply()
    }



        //test
        fun setQ1(q1: String) {
            testPref.edit().putString("q1", q1).apply()
        }

        fun getQ1(): String? {
            return testPref.getString("q1", "")
        }

        fun setQ2(q2: String) {
            testPref.edit().putString("q2", q2).apply()
        }

        fun getQ2(): String? {
            return testPref.getString("q2", "")
        }

        fun setQ3(q3: String) {
            testPref.edit().putString("q3", q3).apply()
        }

        fun getQ3(): String? {
            return testPref.getString("q3", "")
        }

        fun setQ4(q4: String) {
            testPref.edit().putString("q4", q4).apply()
        }

        fun getQ4(): String? {
            return testPref.getString("q4", "")
        }

        fun resetQuestions() {
            testPref.edit().putString("q1", "").apply()
            testPref.edit().putString("q2", "").apply()
            testPref.edit().putString("q3", "").apply()
            testPref.edit().putString("q4", "").apply()
        }
    //uses counter
    fun setCounter(counter:Int){
        useCounterPref.edit().putInt("counter",counter).apply()
    }
    fun getCounter():Int{
        return useCounterPref.getInt("counter",0)}



    fun setIp(ip:String){
        ipPref.edit().putString("ip",ip).apply()
    }
    fun getIp():String?{
        return ipPref.getString("ip","")

    }

    fun resetPrefs(){
        //reset all prefs
        this.setProfileData("","","","","","","","")
        this.setMode("beginner")
        this.resetQuestions()
        this.setRole("")
        this.setCounter(0)
    }



}