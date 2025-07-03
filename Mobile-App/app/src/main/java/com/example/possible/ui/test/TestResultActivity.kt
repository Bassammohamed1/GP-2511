package com.example.possible.ui.test

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.fragment.app.Fragment
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContentProviderCompat.requireContext
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import androidx.lifecycle.lifecycleScope
import com.example.possible.R
import com.example.possible.databinding.ActivityTestBinding
import com.example.possible.databinding.ActivityTestResultBinding
import com.example.possible.model.Test
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.util.adapter.FragmentAdapter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class TestResultActivity : AppCompatActivity() {
    private lateinit var binding: ActivityTestResultBinding
    private var testName = ""
    private var childId = 0
    private var q1r:Int =0
    private var q2r:Int =0
    private var q3r:Int =0
    private var q4r:Int =0
    private var totalr:Int =0
    private var testType = ""
    private var date = ""
    override fun onCreate(savedInstanceState: Bundle?) {
        binding = ActivityTestResultBinding.inflate(layoutInflater)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        initForgetDataView()
        showResults()
        setContentView(binding.root)
        binding.backArrowIV.setOnClickListener {
            finish()
        }
        getChildDataAndView(childId)
        setLevel(totalr)

    }
    private fun initForgetDataView(){
         testName = intent.getStringExtra("testName")!!
         q1r = intent.getIntExtra("q1r",0)
         q2r = intent.getIntExtra("q2r",0)
         q3r = intent.getIntExtra("q3r",0)
         q4r = intent.getIntExtra("q4r",0)
        date = intent.getStringExtra("date")!!
        childId = intent.getIntExtra("childId",0)
        testType = intent.getStringExtra("testType")!!
         totalr = intent.getIntExtra("totalr",0)
    }
    @SuppressLint("SetTextI18n")
    private fun showResults(){
        binding.testName.text = testName
        binding.rq1.text = q1r.toString()
        binding.rq2.text = q2r.toString()
        binding.rq3.text = q3r.toString()
        binding.rq4.text = q4r.toString()
        binding.date.text = date
        binding.testType.text = testType
        binding.rTotal.text = totalr.toString()

    }

    @SuppressLint("SetTextI18n")
    private fun setLevel(total: Int) {
        when (total) {
            0,1, 2 -> {
                binding.level.text = "Bad"
                binding.level.setTextColor(ContextCompat.getColor(this, R.color.error))
            }
            3, 4 -> {
                binding.level.text = "Good"
                binding.level.setTextColor(ContextCompat.getColor(this, R.color.gra))
            }
            5, 6 -> {
                binding.level.text = "Very Good"
                binding.level.setTextColor(ContextCompat.getColor(this, R.color.des))
            }
            7, 8 -> {
                binding.level.text = "Excellent"
                binding.level.setTextColor(ContextCompat.getColor(this, R.color.cal))
            }
        }
    }

    private fun getChildDataAndView(childId:Int){
        lifecycleScope.launch(Dispatchers.IO) {
            val db = LocalRepoImp(this@TestResultActivity)
            val child = db.getChildById(childId)
            withContext(Dispatchers.Main){
                val imageUriString = child.imageUri
                binding.profileIV.setImageURI(imageUriString.toUri())
                binding.userNameTV.text = child.name
            }

        }
    }
}