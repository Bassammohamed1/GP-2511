package com.example.possible.ui.specialist.tests

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Bundle
import android.view.View.GONE
import android.view.View.VISIBLE
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.possible.databinding.ActivityTestsBinding
import com.example.possible.model.SolvedTest
import com.example.possible.model.Test
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.ui.test.dyscalculiaTest.DyscalculiaTestActivity
import com.example.possible.ui.test.dysgraphiaTest.DysgraphiaTestActivity
import com.example.possible.util.adapter.TestAdapter
import com.example.possible.util.listener.TestListener
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class TestsActivity : AppCompatActivity(), TestListener {

    private lateinit var binding: ActivityTestsBinding
    private lateinit var adapter: TestAdapter
    private var testList = ArrayList<Test>()
    private lateinit var db: LocalRepoImp

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        binding = ActivityTestsBinding.inflate(layoutInflater)
        db = LocalRepoImp(this)
        setContentView(binding.root)

        adapter = TestAdapter(testList, this)
        binding.recycler.adapter = adapter // Make sure the adapter is set here

        getTestsList()
        setView()
    }

    private fun setView() {
        binding.backArrowIV.setOnClickListener {
            finish()
        }
        if (testList.isEmpty()) {
            binding.empty.visibility = VISIBLE
            binding.recycler.visibility = GONE
        } else {
            binding.empty.visibility = GONE
            binding.recycler.visibility = VISIBLE
        }
    }

    override fun onTestClick(test: Test) {
        val intent = if (getCategory(test.name) == "BBB" || getCategory(test.name) == "CCC") {
            Intent(this, DysgraphiaTestActivity::class.java)
        } else {
            Intent(this, DyscalculiaTestActivity::class.java)
        }
        intent.putExtra("test", test.name)
        startActivity(intent)
    }

    override fun onDeleteClick(test: Test, position: Int) {
        // Not implemented yet
    }

    override fun onSolvedClick(test: SolvedTest, position: Int) {
        TODO("Not yet implemented")
    }

    override fun onSolvedDelete(test: SolvedTest, position: Int) {
        TODO("Not yet implemented")
    }

    private fun getCategory(examName: String): String {
        return examName.substring(6)
    }

    @SuppressLint("NotifyDataSetChanged")
    private fun getTestsList() {
        lifecycleScope.launch(Dispatchers.IO) {
            val tests = db.getAllTests()
            withContext(Dispatchers.Main) {

                testList.clear() // Clear the old data
                testList.addAll(tests) // Add the new data
                adapter.notifyDataSetChanged() // Notify the adapter to update the UI

                setView() // Update the visibility of recycler & empty views
            }
        }
    }
}
