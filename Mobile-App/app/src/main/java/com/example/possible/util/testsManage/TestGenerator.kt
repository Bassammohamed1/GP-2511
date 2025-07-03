package com.example.possible.util.testsManage

import android.content.Context
import android.widget.Toast
import com.example.possible.model.Question
import com.example.possible.model.Test
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.repo.remote.RetrofitBuilder
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

object TestGenerator {
    private const val TEST_QUES_NUM = 4

   data class ApiTestResponse(
       val testName: String,
       val testCategory: String,
       val questionsNo: String,
       val questions: List<TestQuestionForApi>,

   )


    @OptIn(DelicateCoroutinesApi::class)
    private fun storeTest(test:Test, context: Context) {
        val localRepo = LocalRepoImp(context)
        GlobalScope.launch(Dispatchers.IO) {
            localRepo.insertTest(test)
        }

    }

    @OptIn(DelicateCoroutinesApi::class)
    fun sendTest(onStart: () -> Unit,test:Test, context: Context, pref: SharedPref,onEnd: () -> Unit) {
        onStart()
        val token = "Bearer ${pref.getToken()}"
        val apiTest = convertFromLocalTestToApiTest(test)
        GlobalScope.launch(Dispatchers.IO) {
           try {

            val response = RetrofitBuilder.sendExamOnlineService.sendExamOnline(token, apiTest)
            if (response.isSuccessful) {
                val body = response.body()
                if (body != null) {
                    storeTest(test, context)
                    withContext(Dispatchers.Main) {
                        Toast.makeText(context,body.message, Toast.LENGTH_SHORT).show()
                        onEnd()
                    }
                }
            }

        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                Toast.makeText(context, "Error: Broken internet connection, check your connection", Toast.LENGTH_SHORT).show()
                onEnd()
            }
           }
        }

    }

    fun convertFromApiTestToLocalTest(apiTest: ApiTestResponse): Test {
        val testName = apiTest.testName
        val testType = apiTest.testCategory
        val questions = apiTest.questions
        val childrenId = emptyList<String>()
        val localQuestions = ArrayList<Question>()
        for (question in questions) {
            localQuestions.add(convertApiQuesToLocalQues(question))
        }
        return Test(testName, testType, localQuestions, childrenId)
    }

    private fun convertApiQuesToLocalQues(apiQues: TestQuestionForApi): Question {
        val questionText = apiQues.questionText
        val questionLevel = apiQues.questionAnswer
        val questionType = apiQues.questionType
        return Question(questionType, questionText, questionLevel)
    }


    private fun convertFromLocalTestToApiTest(test: Test):ApiTest{
        val testName = test.name
        val testType = test.type
        val questions = test.listOfQuestions
        val childrenId = test.childrenId
        val apiQuestions = ArrayList<TestQuestionForApi>()
        for (question in questions) {
            apiQuestions.add(convertLocalQuesToApiQues(question))
        }
        return ApiTest(testName, testType, TEST_QUES_NUM.toString(), apiQuestions, childrenId)
    }
    private fun convertLocalQuesToApiQues(localQues: Question): TestQuestionForApi {
        val questionText = localQues.question
        val questionLevel = localQues.level
        val questionType = localQues.type
        return TestQuestionForApi(questionText, questionLevel, questionType)
    }

}