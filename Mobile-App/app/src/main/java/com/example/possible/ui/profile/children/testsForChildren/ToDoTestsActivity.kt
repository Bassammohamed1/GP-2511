package com.example.possible.ui.profile.children.testsForChildren

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.example.possible.R
import com.example.possible.databinding.ActivityToDoTestsBinding
import com.example.possible.ui.report.ReadingFragment
import com.example.possible.ui.report.WritingFragment
import com.example.possible.util.adapter.FragmentAdapter
import com.google.android.material.tabs.TabLayoutMediator

class ToDoTestsActivity : AppCompatActivity() {
    private lateinit var binding: ActivityToDoTestsBinding
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        binding = ActivityToDoTestsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        val tabLayout = binding.tabLayout
        val viewPager = binding.viewPager
        val id = intent.getIntExtra("childId",0)

        val adapter = FragmentAdapter(this, arrayListOf(
            TestsToDoFragment().newInstance(id),
            TestsDoneFragment().newInstance(id)
        )
        )
        viewPager.adapter = adapter

        // ربط TabLayout مع ViewPager2
        TabLayoutMediator(tabLayout, viewPager) { tab, position ->
            tab.text = when (position) {
                0 -> "To Do"
                1 -> "Done"
                else -> "Tab"
            }
        }.attach()
    }
}

