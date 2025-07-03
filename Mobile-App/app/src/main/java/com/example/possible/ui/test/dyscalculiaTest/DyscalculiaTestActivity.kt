package com.example.possible.ui.test.dyscalculiaTest

import DialogBuilder
import android.annotation.SuppressLint
import android.os.Bundle
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.viewpager2.widget.ViewPager2
import com.example.possible.databinding.ActivityTestBinding
import com.example.possible.model.Question
import com.example.possible.model.SolvedTest
import com.example.possible.model.Test
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.ui.test.TestResultActivity
import com.example.possible.util.adapter.FragmentAdapter
import kotlinx.coroutines.*

class DyscalculiaTestActivity : AppCompatActivity() {
    private lateinit var binding: ActivityTestBinding
    private lateinit var test: Test
    private lateinit var frameAdapter: FragmentAdapter
    private lateinit var db: LocalRepoImp
    private lateinit var pref: SharedPref

    private val fragments = ArrayList<Fragment>()
    private var result = 0
    private var childId = -1
    private var testName = ""
    private var q1 = 0
    private var q2 = 0
    private var q3 = 0
    private var q4 = 0

    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityTestBinding.inflate(layoutInflater)
        enableEdgeToEdge()
        setContentView(binding.root)

        db = LocalRepoImp(this)
        pref = SharedPref(this)

        initForTest()
        setupPageChangeListener()
    }

    private fun setupTestFragments() {
        test.listOfQuestions.forEach { setTheSuitableFrameForTheQuestions(it) }
        frameAdapter = FragmentAdapter(this, fragments)
        binding.viewPager.adapter = frameAdapter
        binding.dotsIndicator.attachTo(binding.viewPager)
    }

    private fun setTheSuitableFrameForTheQuestions(q: Question) {
        val fragment = when (q.type) {
            "Adding", "Subtraction" -> AddingFragment().getInstance(q.question, q.type)
            "Arithmetic Sequence" -> ArithmeticFragment().getInstance(q.question)
            "Inequality" -> ComparisonFragment().getInstance(q.question)
            else -> null
        }
        fragment?.let { fragments.add(it) }
    }

    private fun calculateResult(): Int = fragments.sumOf {
        when (it) {
            is AddingFragment -> it.getResult()
            is ArithmeticFragment -> it.getResults()
            is ComparisonFragment -> it.getResult()
            else -> 0
        }
    }
    private fun calcEachQuestionResult(index:Int):Int{
        return when (fragments[index]) {
            is AddingFragment -> (fragments[index] as AddingFragment).getResult()
            is ArithmeticFragment -> (fragments[index] as ArithmeticFragment).getResults()
            is ComparisonFragment -> (fragments[index] as ComparisonFragment).getResult()
            else -> 0
        }

    }

    private fun setupPageChangeListener() {
        binding.viewPager.registerOnPageChangeCallback(object : ViewPager2.OnPageChangeCallback() {
            @SuppressLint("SetTextI18n")
            override fun onPageSelected(position: Int) {
                binding.pages.text = "${position + 1}/${fragments.size}"
            }
        })
    }

    @SuppressLint("SetTextI18n")
    private fun initForTest() {
        if (pref.getRole() == "User") {
            childId = intent.getIntExtra("childId", -1)
            testName = intent.getStringExtra("test") ?: ""
            if (childId == -1) finish() else getTheTestToViewToTheChild()
            setControllerForUser()
        } else {
            testName = intent.getStringExtra("test") ?: ""
            binding.endSession.text = "Exit"
            binding.endSession.setOnClickListener { finish() }
            getTest()
        }
    }

    private fun setControllerForUser() {
        binding.endSession.setOnClickListener {
            DialogBuilder.showAlertDialog(
                this,
                "Are you sure to end the session?", "Have you finished the test!", "Yes", "No",
                onConfirm = {
                    lifecycleScope.launch {
                        result = calculateResult()
                        q1 = calcEachQuestionResult(0)
                        q2 = calcEachQuestionResult(1)
                        q3 = calcEachQuestionResult(2)
                        q4 = calcEachQuestionResult(3)
                        saveTestResult()
                    }
                },{}
            )
        }
    }

    private suspend fun saveTestResult() {
        withContext(Dispatchers.IO) {
            val db = LocalRepoImp(this@DyscalculiaTestActivity)
            val child = db.getChildById(childId)
            val newSolvedTest = SolvedTest(test.name, test.type, q1, q2, q3, q4, result, getCurrentDate())
            val newList =child.childSolvedTests as MutableList<SolvedTest>
            newList.add(newSolvedTest)
            db.updateSolvedTests(childId,newList)
            withContext(Dispatchers.Main) {
                Toast.makeText(this@DyscalculiaTestActivity, "Correction has been approved", Toast.LENGTH_SHORT).show()
                goTiTheResult()
                finish()
            }
        }
    }


    private fun goTiTheResult(){
        val intent = android.content.Intent(this, TestResultActivity::class.java)
        intent.putExtra("testName",test.name)
        intent.putExtra("q1r",q1)
        intent.putExtra("childId",childId)
        intent.putExtra("q2r",q2)
        intent.putExtra("q3r",q3)
        intent.putExtra("q4r",q4)
        intent.putExtra("testType",test.type)
        intent.putExtra("date",getCurrentDate())
        intent.putExtra("totalr",result)
        startActivity(intent)
    }

    private fun getCurrentDate(): String {
        val current = System.currentTimeMillis()
        return android.text.format.DateFormat.format("dd-MM-yyyy hh:mm:ss", current).toString()
    }

    private fun getTest() {
        lifecycleScope.launch(Dispatchers.IO) {
            test = db.getTestByName(testName) ?: Test("", "", emptyList(), emptyList())
            withContext(Dispatchers.Main) {
                setupTestFragments()
            }
        }
    }

    private fun getTheTestToViewToTheChild() {
        lifecycleScope.launch(Dispatchers.IO) {
            val child = db.getChildById(childId)
            val foundTest = child.childTests.find { it.name == testName }
            if (foundTest != null) {
                test = foundTest
                withContext(Dispatchers.Main) {
                    setupTestFragments()
                }
            } else {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@DyscalculiaTestActivity, "Test not found for this child", Toast.LENGTH_SHORT).show()
                    finish()
                }
            }
        }
    }

    @Deprecated("This method has been deprecated in favor of using the\n      {@link OnBackPressedDispatcher} via {@link #getOnBackPressedDispatcher()}.\n      The OnBackPressedDispatcher controls how back button events are dispatched\n      to one or more {@link OnBackPressedCallback} objects.")
    override fun onBackPressed() {
        if(pref.getRole()=="User")
        {        DialogBuilder.showAlertDialog(
            this,
            "Are you sure to end the session  without correction?","End Session !","Yes","No",
            onConfirm = {
                super.onBackPressed()
            },
            onCancel = {

            }
        )
        }
    }

}