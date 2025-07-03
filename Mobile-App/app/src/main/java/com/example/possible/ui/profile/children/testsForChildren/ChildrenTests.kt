package com.example.possible.ui.profile.children.testsForChildren

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Bundle
import android.view.View.GONE
import android.view.View.VISIBLE
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import com.example.possible.databinding.ActivityChildrenTestsBinding
import com.example.possible.model.Child
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.util.adapter.ChildrenAdapter
import com.example.possible.util.listener.ChildListener

class ChildrenTests : AppCompatActivity(), ChildListener {
    private lateinit var binding: ActivityChildrenTestsBinding
    private lateinit var children: ArrayList<Child>
    private lateinit var adapter: ChildrenAdapter
    private lateinit var db: LocalRepoImp
    private lateinit var sharedPref: SharedPref
    private lateinit var viewModel: ChildrenTestsViewModel
    private var childrenAfterLoading = emptyList<Child>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        binding = ActivityChildrenTestsBinding.inflate(layoutInflater)
        setContentView(binding.root)


        binding.backArrowIV.setOnClickListener {
            finish()
        }
    }

    private fun initVariables() {
        children = arrayListOf()
        sharedPref = SharedPref(this)
        db = LocalRepoImp(this)
        viewModel = ViewModelProvider(this)[ChildrenTestsViewModel::class.java]
        adapter = ChildrenAdapter(children, this, sharedPref).apply { setTestMode(true) }
        loadChildren()
    }

    private fun setupRecyclerView() {
        binding.recyclerView.adapter = adapter
    }

    @SuppressLint("NotifyDataSetChanged")
    private fun observeViewModel() {
        viewModel.children.observe(this) {
            children.clear()
            children.addAll(it)
            adapter.updateData(children)
            adapter.notifyDataSetChanged()
        }

        viewModel.manageAllChildren(
            onStart = { binding.loadingView.visibility = VISIBLE },
            context = this,
            onFinish = {
                binding.loadingView.visibility = GONE
            }
        )
    }


    private fun loadChildren() {
        viewModel.getAllChildren(
            context = this,
            onEmpty = {
                binding.recyclerView.visibility = GONE
                binding.hint.visibility = VISIBLE
            },
            onNotEmpty = {
                binding.recyclerView.visibility = VISIBLE
                binding.hint.visibility = GONE
            })

    }

    @SuppressLint("NotifyDataSetChanged")
    override fun onResume() {
        super.onResume()
        initVariables()
        setupRecyclerView()
        observeViewModel()
    }

    override fun onClick(child: Child) {
        val intent = Intent(this,ToDoTestsActivity::class.java)
        intent.putExtra("childId", child.id)
        startActivity(intent)
    }

    override fun onDelete(position: Int, child: Child) {
        // Not implemented yet
    }


}
