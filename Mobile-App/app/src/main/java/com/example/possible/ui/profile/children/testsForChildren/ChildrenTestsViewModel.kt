package com.example.possible.ui.profile.children.testsForChildren

import android.content.Context
import android.widget.Toast
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.possible.model.Child
import com.example.possible.model.Test
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.repo.remote.RetrofitBuilder
import com.example.possible.util.helper.InterNetHelper.isInternetAvailable
import com.example.possible.util.testsManage.TestGenerator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.lang.Exception

class ChildrenTestsViewModel : ViewModel() {

    private val _children = MutableLiveData<List<Child>>()
    val children: LiveData<List<Child>> = _children



    fun manageAllChildren(onStart: () -> Unit, context: Context, onFinish: () -> Unit) {
        onStart()
        val db = LocalRepoImp(context)
        val sharedPref = SharedPref(context)
        val token = sharedPref.getToken()
        val authToken = "Bearer $token"

        if (!isInternetAvailable(context)) {
            Toast.makeText(context, "No Internet Connection", Toast.LENGTH_SHORT).show()
            onFinish()
            return
        }

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val allChildren = db.getAllChildren()
                if (allChildren.isEmpty()) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(context, "No children found.", Toast.LENGTH_SHORT).show()
                        onFinish()
                    }
                    return@launch
                }

                allChildren.forEach { child ->
                    fetchAndSaveChildTests(child.id, authToken, db, context)
                }

                withContext(Dispatchers.Main) {
                    onFinish()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(context, "Error managing children: ${e.message}", Toast.LENGTH_LONG).show()
                    onFinish()
                }
            }
        }
    }

    private suspend fun fetchAndSaveChildTests(childId: Int, token: String, db: LocalRepoImp, context: Context) {
        try {
            val response = RetrofitBuilder.getChildTests.getChildTest(token, childId)

            if (response.isSuccessful) {
                response.body()?.let { apiTests ->
                    updateChildTestsIfNeeded(apiTests, db, childId, context)
                }
            } else {
                withContext(Dispatchers.Main) {
                    Toast.makeText(context, "Failed to fetch tests for child $childId", Toast.LENGTH_SHORT).show()
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                Toast.makeText(context, "Error fetching tests: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun updateChildTestsIfNeeded(
        apiTests: List<TestGenerator.ApiTestResponse>,
        db: LocalRepoImp,
        childId: Int,
        context: Context
    ) {
        if (apiTests.isEmpty()) return

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val child = db.getChildById(childId)
                val currentTests = child.childTests.toMutableList()
                var isUpdated = false

                apiTests.forEach { apiTest ->
                    if (!isTestAlreadyAdded(apiTest.testName, currentTests)) {
                        val newTest = TestGenerator.convertFromApiTestToLocalTest(apiTest)
                        currentTests.add(newTest)
                        db.updateChildTests(childId, currentTests)
                        isUpdated = true
                    }
                }

                if (isUpdated) {
                    val allChildren = db.getAllChildren()
                    _children.postValue(allChildren)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(context, "Error updating child tests: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun isTestAlreadyAdded(testName: String, tests: List<Test>): Boolean {
        return tests.any { it.name == testName }
    }

    fun getAllChildren(context: Context, onEmpty: () -> Unit, onNotEmpty: (List<Child>) -> Unit) {
        val db = LocalRepoImp(context)

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val allChildren = db.getAllChildren()

                withContext(Dispatchers.Main) {
                    if (allChildren.isEmpty()) {
                        onEmpty()
                        Toast.makeText(context, "No children available.", Toast.LENGTH_SHORT).show()
                    } else {
                        onNotEmpty(allChildren)
                        _children.value = allChildren
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(context, "Error retrieving children: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }
}
