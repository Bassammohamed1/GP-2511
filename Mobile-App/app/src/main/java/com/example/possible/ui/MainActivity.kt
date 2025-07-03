package com.example.possible.ui

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.util.Log
import android.view.View.GONE
import android.view.View.VISIBLE
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.possible.databinding.ActivityMainBinding
import com.example.possible.model.User
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.ui.math.MainMathActivity
import com.example.possible.ui.profile.ProfileActivity
import com.example.possible.ui.profile.children.addChild.AddChildActivity
import com.example.possible.ui.reading.ReadingMainActivity
import com.example.possible.ui.signLogin.Login.LoginActivity
import com.example.possible.util.LogoutHandler
import com.example.possible.util.helper.ChildTraker
import com.example.possible.util.helper.dataManager.AppDataManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var appUserData : User
    private val Handler = Handler()
    private lateinit var pref: SharedPref
    private var childId: Int =-1
    private lateinit var db : LocalRepoImp
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        binding = ActivityMainBinding.inflate(layoutInflater)

        pref = SharedPref(this)
        appUserData = pref.getProfileDetails()
        childId = intent.getIntExtra("childId", -1)
        db = LocalRepoImp(this)
        assignValuesToChildTracker(childId)






        binding.letters.setOnClickListener {
            numbersOrLetters(result = "letters")
        }
        binding.numbers.setOnClickListener {
            numbersOrLetters(result = "numbers")
        }
        binding.hideView.setOnClickListener{
            hideTheView()
        }
        binding.readingBtn.setOnClickListener {
            val intent = Intent(this, ReadingMainActivity::class.java)
            startActivity(intent)
        }
        binding.mathBtn.setOnClickListener {
            val intent = Intent(this, MainMathActivity::class.java)
            startActivity(intent)
        }
        binding.helloLayout.setOnClickListener {
            goToProfile()
        }
        binding.profileIV.setOnClickListener {
           goToProfile()
        }
        binding.settingIV.setOnClickListener {
          goToProfile()
        }
        binding.activeChild.setOnClickListener {
            goToChildProfile()
        }
        setContentView(binding.root)

    }

    private fun goToChildProfile() {
        intent = Intent(this, AddChildActivity::class.java)
        intent.putExtra("childId", childId)
        intent.putExtra("mode", "edit")
        startActivity(intent)
    }

    private fun goToProfile() {
        val intent = Intent(this, ProfileActivity::class.java)
        startActivity(intent)
    }
    private fun numbersOrLetters(result: String){
        viewBeginnerOrProf()
        binding.beginnerIV.setOnClickListener {
            pref.setMode("beginner")
            sendResult(result)
        }
        binding.proIV.setOnClickListener {
            pref.setMode("professional")
            sendResult(result)
        }
    }
    private fun viewBeginnerOrProf() {
        binding.beginnerOrProf.visibility= VISIBLE
        binding.activeChild.visibility= GONE
        binding.beginnerOrProf.animate().scaleX(0f).scaleY(0f).setDuration(0).start()
        binding.beginnerOrProf.animate().scaleX(1f).scaleY(1f).setDuration(500).start()
    }

    private fun hideTheView(){
        Handler.postDelayed({
            binding.beginnerOrProf.animate().scaleX(0f).scaleY(0f).setDuration(300).withEndAction{
                binding.beginnerOrProf.visibility= GONE
                binding.activeChild.visibility= VISIBLE
            }.start()
        },200)

    }


    private fun sendResult(result: String) {
        val intent = Intent(this, LettersNumbersActivity::class.java)
        intent.putExtra("result", result)
        startActivity(intent)
        hideTheView()
    }

    override fun onResume() {
        super.onResume()
        AppDataManager.viewProfileImage(binding.profileIV,pref,this)
        binding.userNameTV.text=AppDataManager.getProfileDetails(pref).name
        Log.d("ImageProfile"," ${AppDataManager.getProfileDetails(pref).imagePath} from main activity")
        isFromLogout()
    }
    @SuppressLint("SetTextI18n")
    private fun assignValuesToChildTracker(childId: Int) {
        ChildTraker.setChildId(childId)
        lifecycleScope.launch {
            val child = db.getChildById(childId)
            withContext(Dispatchers.Main) {
                binding.activeChild.text = "Active child : ${child.name}"
            }
            ChildTraker.setReadingRate(child.readingRate)
            ChildTraker.setWritingRate(child.writingRate)
        }
    }

    private fun isFromLogout(){
             if(LogoutHandler.isLoggingOUt){
            clearAll()
                 LogoutHandler.clearAllLoggedData(this)
            finish()
             }

        }


    private fun clearAll() {
        val isDeleted = deleteDatabase("child_database")
        if (isDeleted) {
            Log.d("Database", "Database deleted successfully")
        } else {
            Log.d("Database", "Failed to delete database")
        }
    }
}