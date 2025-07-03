package com.example.possible.ui.specialist

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import com.example.possible.databinding.ActivitySpecialistMainBinding
import com.example.possible.repo.local.SharedPref
import com.example.possible.ui.profile.ProfileActivity
import com.example.possible.ui.profile.children.Children
import com.example.possible.ui.signLogin.Login.LoginActivity
import com.example.possible.ui.specialist.tests.TestTypesActivity
import com.example.possible.ui.specialist.tests.TestsActivity
import com.example.possible.util.LogoutHandler
import com.example.possible.util.helper.dataManager.AppDataManager

class SpecialistMainActivity : AppCompatActivity() {
    private lateinit var binding: ActivitySpecialistMainBinding
    private lateinit var pref: SharedPref
    override fun onCreate(savedInstanceState: Bundle?) {
        binding = ActivitySpecialistMainBinding.inflate(layoutInflater)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        pref = SharedPref(this)
        setContentView(binding.root)
        setControllers()


    }

    private fun setControllers() {
        binding.childrenLL.setOnClickListener {
            val intent = Intent(this, Children::class.java)
            intent.putExtra("mode", "view")
            startActivity(intent)
        }
        binding.newTest.setOnClickListener {
            val intent = Intent(this, TestTypesActivity::class.java)
            startActivity(intent)
        }
        binding.Tests.setOnClickListener {
            val intent = Intent(this, TestsActivity::class.java)
            startActivity(intent)
        }

        binding.profileIV.setOnClickListener {
            goToProfile()
        }
        binding.header.setOnClickListener {
            goToProfile()
        }


    }

    private fun goToProfile() {
        val intent = Intent(this, ProfileActivity::class.java)
        startActivity(intent)
    }

    override fun onResume() {
        super.onResume()
        binding.userNameTV.text = pref.getProfileDetails().name
        AppDataManager.viewProfileImage(binding.profileIV, pref, this)
        Log.d(
            "ImageProfile",
            " ${AppDataManager.getProfileDetails(pref).imagePath} from main activity"
        )
        isFromLogout()
    }

    private fun isFromLogout() {
        if (LogoutHandler.isLoggingOUt) {
            clearAll()
            val intent = Intent(this, LoginActivity::class.java)
            startActivity(intent)
            finish()

        }
    }

    private fun clearAll() {
        LogoutHandler.clearAllLoggedData(this)
        // deleteTheDatabase
        val isDeleted = deleteDatabase("child_database")
        if (isDeleted) {
            Log.d("Database", "Database deleted successfully")
        } else {
            Log.d("Database", "Failed to delete database")
        }
    }

}

