package com.example.possible.ui.test.dysgraphiaTest

import DialogBuilder
import android.annotation.SuppressLint
import android.content.Context
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.example.possible.R
import com.example.possible.databinding.ActivityDysgraphiaTestBinding
import com.example.possible.model.Question
import com.example.possible.model.SolvedTest
import com.example.possible.model.Test
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.ui.drawing.DrawingFragment
import com.example.possible.ui.test.TestResultActivity
import com.example.possible.ui.tracing.TracingFragment
import com.example.possible.util.TestDecoder
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DysgraphiaTestActivity : AppCompatActivity() {
    private lateinit var fragments: MutableList<Fragment?>
    private lateinit var binding: ActivityDysgraphiaTestBinding
    private lateinit var test: Test
    private var currentIndex = 0 // Track the current fragment
    private var result: Int = 0
    private lateinit var db: LocalRepoImp
    private var testName =""
    private var q1:Int =0
    private var q2:Int =0
    private var q3:Int =0
    private var q4:Int =0
    private var childId=-1
    private lateinit var pref: SharedPref


    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        db = LocalRepoImp(this)
        binding = ActivityDysgraphiaTestBinding.inflate(layoutInflater)
        setContentView(binding.root)

        test = Test("","", listOf(), listOf())

        initForTest()



        binding.theNext.setOnClickListener {
            if (currentIndex < test.listOfQuestions.size - 1) {
                currentIndex++
                binding.pages.text = "${currentIndex + 1}/${test.listOfQuestions.size}"
                loadFragment(currentIndex)
            }
        }

        // Previous button click listener
        binding.backToPrevious.setOnClickListener {
            if (currentIndex > 0) {
                currentIndex--
                binding.pages.text = "${currentIndex + 1}/${test.listOfQuestions.size}"
                loadFragment(currentIndex)
            }
        }
    }


    private fun loadFragment(index: Int) {
        val fragmentManager = supportFragmentManager
        val transaction = fragmentManager.beginTransaction()

        // Hide all fragments
        fragments.forEachIndexed { i, fragment ->
            if (fragment != null && fragment.isAdded) {
                transaction.hide(fragment)
            }
        }

        // If the fragment is already created, show it
        var fragment = fragments[index]
        if (fragment == null) {
            // Create a new fragment only if it doesn't exist
            fragment = createFragmentForQuestion(test.listOfQuestions[index])
            fragments[index] = fragment
            transaction.add(R.id.frameT, fragment, "fragment_$index")
        } else {
            transaction.show(fragment)
        }

        // Commit the transaction
        transaction.commit()
    }

    private fun createFragmentForQuestion(q: Question): Fragment {
        return when (q.type) {
            "Write a letter", "Write a number" -> {
                val (index, type,level) = TestDecoder.decodeLetterOrNumber(q.question)
                if(level == "beginner"){
                    TracingFragment().getInstance(index, type)
                }
                else{
                    DrawingFragment().getInstance(index, type)
                }
            }
            "Sentence Combining"->{
                SentenceCombiningFragment().newInstance(q.question)
            }
            "Complete"->{
                SentenceCompletingFragment().newInstance(q.question)
            }
            else -> throw IllegalArgumentException("Unsupported question type")
        }
    }
    private suspend fun calcTheResult(): Int {
        if (fragments.isEmpty()) {
            return 0
        }

        var result = 0

        for (fragment in fragments) {
            val indexNum = fragments.indexOf(fragment)
            var currentQResult = 0
            when (fragment) {
                is TracingFragment -> {
                    currentQResult =fragment.getResultsForTest()
                    result += fragment.getResultsForTest()
                }
                is DrawingFragment -> {
                    if (fragment.getResult()) {
                        result += 2
                        currentQResult = 2

                    }
                }
                is SentenceCompletingFragment -> {
                    result += fragment.returnResult()
                    currentQResult = fragment.returnResult()

                }
                is SentenceCombiningFragment -> {
                    result += fragment.returnResult()
                    currentQResult = fragment.returnResult()
                }
            }
            when(indexNum){
                0->{
                    q1 = currentQResult
                }
                1->{
                    q2 = currentQResult

                }
                2->{
                    q3 = currentQResult
                }
                3->{
                    q4 = currentQResult
                }
            }
        }

        return result
    }
    @SuppressLint("SetTextI18n")
    private fun getTest(){
        lifecycleScope.launch(Dispatchers.IO) {
            test = db.getTestByName(testName)!!
            withContext(Dispatchers.Main) {
                binding.pages.text = "1/${test.listOfQuestions.size}"
                binding.nameOfTest.text = test.name
                binding.typeOfTest.text = test.type
                fragments = MutableList(test.listOfQuestions.size) { null } // Array to store fragments
                loadFragment(currentIndex)
            }
        }
    }


    // for user Child


    @SuppressLint("SetTextI18n")
    private fun getTheTestToViewToTheChild(id:Int, testName:String){
        lifecycleScope.launch(Dispatchers.IO) {
            val child = db.getChildById(id)
            val childTests = child.childTests
            var foundTest: Test? = null

            for(test in childTests){
                if(test.name == testName){
                    foundTest = test
                    break
                }
            }

            if (foundTest != null) {
                this@DysgraphiaTestActivity.test = foundTest

                withContext(Dispatchers.Main) {
                    binding.pages.text = "1/${test.listOfQuestions.size}"
                    binding.nameOfTest.text = test.name
                    binding.typeOfTest.text = test.type
                    fragments = MutableList(this@DysgraphiaTestActivity.test.listOfQuestions.size) { null } // Array to store fragments
                    loadFragment(currentIndex)
                }
            } else {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@DysgraphiaTestActivity, "Test not found for this child", Toast.LENGTH_SHORT).show()
                    finish()
                }
            }
        }
    }



    @SuppressLint("SuspiciousIndentation")
    @OptIn(DelicateCoroutinesApi::class)
    private fun setControllerForUser(context: Context){
        binding.endSession.setOnClickListener {
            DialogBuilder.showAlertDialog(
                this,
                "Are you sure to end the session?", "Have you finished the test!", "Yes", "No",
                onConfirm = {
                    binding.loadingView.visibility = View.VISIBLE
                    GlobalScope.launch {
                        result = calcTheResult()
                        withContext(Dispatchers.Main){
                            binding.loadingView.visibility = View.GONE
                        }
                        makeTheTestSolved(context,test.name,test.type,q1,q2,q3,q4,result)
                    }
                },
                onCancel = {

                }
            )
        }

    }
    @OptIn(DelicateCoroutinesApi::class)
    private fun  makeTheTestSolved(context: Context, testName:String, testType:String, q1:Int, q2:Int, q3:Int, q4:Int, totalResult:Int){
        val newSolvedTest = SolvedTest(testName,testType,q1,q2,q3,q4,totalResult,getTheCurrentDate())
        GlobalScope.launch(Dispatchers.IO) {
            val db = LocalRepoImp(context)
            val child = db.getChildById(childId)
            val solvedTests = child.childSolvedTests as MutableList
            solvedTests.add(newSolvedTest)
            db.updateSolvedTests(childId,solvedTests.toList())
            withContext(Dispatchers.Main){
                Toast.makeText(this@DysgraphiaTestActivity, "Correction has been approved", Toast.LENGTH_SHORT).show()
                goTiTheResult()
                finish()
            }

        }

    }
    private fun getTheCurrentDate():String{
        val current = System.currentTimeMillis()
        val formattedDate = android.text.format.DateFormat.format("dd-MM-yyyy hh:mm:ss", current)
        return formattedDate.toString()
    }

    @SuppressLint("SetTextI18n")
    private fun initForTest(){
        pref = SharedPref(this)
        if(pref.getRole()=="User"){



            val id = intent.getIntExtra("childId",-1)
            val testName = intent.getStringExtra("test")?:""
            if(id == -1){
                finish()
            }
            childId = id
            getTheTestToViewToTheChild(id,testName)
            setControllerForUser(this)
        }
        else{
            testName = intent.getStringExtra("test")?:""
            binding.endSession.text = "Exit"
            binding.endSession.setOnClickListener {
                finish()
            }
            getTest()

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
        intent.putExtra("date",getTheCurrentDate())
        intent.putExtra("totalr",result)
        startActivity(intent)
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
