package com.example.possible.ui.report

import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.annotation.SuppressLint
import android.net.Uri
import android.os.Bundle
import android.widget.ProgressBar
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.viewpager2.widget.ViewPager2
import com.example.possible.databinding.ActivityReportBinding
import com.example.possible.model.Child
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.ui.profile.children.testsForChildren.TestsDoneFragment
import com.example.possible.util.adapter.FragmentAdapter
import com.google.android.material.tabs.TabLayoutMediator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ReportActivity : AppCompatActivity() {
    private var childId = 0
    private var readingRate = 0
    private var writingRate = 0
    private var child: Child? = null
    private var name = ""
    private var imageUri: Uri? = null
    private lateinit var db: LocalRepoImp
    private lateinit var pref: SharedPref
    private lateinit var binding: ActivityReportBinding
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        binding = ActivityReportBinding.inflate(layoutInflater)
        setContentView(binding.root)
        db = LocalRepoImp(this)
        pref = SharedPref(this)
        childId = intent.getIntExtra("childId", 1)
        getTheChildToView(childId)
        setControllers()

            }


    @SuppressLint("SetTextI18n")
    private fun getTheChildToView(childId: Int){
        lifecycleScope.launch(Dispatchers.IO) {
            child = db.getChildById(childId)
            withContext(Dispatchers.Main){
                if (child != null) {
                    ////////SET_DATA////////////////
                    name = child!!.name
                    imageUri = Uri.parse(child!!.imageUri)
                    ///////////SET_VIEW////////////////
                    binding.childName.text = child!!.name
                    readingRate = child!!.readingRate
                    val readingDays = child!!.readingDays
                    val latestDayOfReading = child!!.latestReadingDay
                    writingRate = child!!.writingRate
                    val joiningDate = child!!.date
                    val writingDays = child!!.writingDays
                    val latestDayOfWriting = child!!.latestWritingDay



                    val adapter = FragmentAdapter(this@ReportActivity, arrayListOf(
                        ReadingFragment().newInstance(readingRate,readingDays,latestDayOfReading?:""),
                        WritingFragment().newInstance(writingRate,writingDays,latestDayOfWriting?:""),
                    )
                    )
                    binding.viewPager.adapter = adapter
                    // ربط TabLayout مع ViewPager2
                    TabLayoutMediator(binding.tabLayout, binding.viewPager) { tab, position ->
                        tab.text = when (position) {
                            0 -> "Reading"
                            1 -> "Writing"
                            else -> "Tab"
                        }
                    }.attach()
                    binding.childImage.setImageURI(Uri.parse(child!!.imageUri))
                    binding.joiningDate.text = "Joining Date : $joiningDate"
                    }
            }

        }
    }



    private fun setControllers(){
        binding.backArrowIV.setOnClickListener{
            finish()
        }
        binding.viewPager.registerOnPageChangeCallback(object : ViewPager2.OnPageChangeCallback() {
            @SuppressLint("SetTextI18n")
            override fun onPageSelected(position: Int) {
                super.onPageSelected(position)
                when (position) {
                    0 -> {
                        animateProgressWithText(binding.progressBar, binding.progressValue, readingRate)
                    }
                    1 -> {
                        animateProgressWithText(binding.progressBar, binding.progressValue, writingRate)
                    }

                }
                }
        })


    }


    @SuppressLint("SetTextI18n")
    fun animateProgressWithText(progressBar: ProgressBar, textView: TextView, newProgress: Int) {
        val animator = ValueAnimator.ofInt(progressBar.progress, newProgress)
        animator.duration = 1000 // مدة الأنيميشن (1 ثانية)

        animator.addUpdateListener { animation ->
            val animatedValue = animation.animatedValue as Int
            progressBar.progress = animatedValue
            textView.text = "$animatedValue%" // تحديث النص مع الحركة
        }

        animator.start()
    }

}




