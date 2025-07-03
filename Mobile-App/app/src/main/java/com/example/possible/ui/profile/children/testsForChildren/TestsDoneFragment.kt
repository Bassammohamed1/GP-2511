package com.example.possible.ui.profile.children.testsForChildren

import DialogBuilder
import android.content.Intent
import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.lifecycle.lifecycleScope
import com.example.possible.databinding.FragmentTestsDoneBinding
import com.example.possible.model.SolvedTest
import com.example.possible.model.Test
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.ui.test.TestResultActivity
import com.example.possible.util.adapter.SolvedTestAdapter
import com.example.possible.util.listener.TestListener
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext


class TestsDoneFragment : Fragment() , TestListener{
    private lateinit var binding: FragmentTestsDoneBinding
    private var id = 0
    fun newInstance(id:Int):TestsDoneFragment{
        val args = Bundle()
        args.putInt("id",id)
        val fragment = TestsDoneFragment()
        fragment.arguments = args
        return fragment
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {

        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        // Inflate the layout for this fragment
        binding = FragmentTestsDoneBinding.inflate(inflater, container, false)
        id = arguments?.getInt("id")!!
        return binding.root
    }


    private fun setTests(tests: List<SolvedTest>) {
        val adapter = SolvedTestAdapter(tests as ArrayList<SolvedTest>,this)
        binding.recyclerView.adapter = adapter
    }

    private fun  getDoneTests(id:Int){
        lifecycleScope.launch(Dispatchers.IO) {
            val db = LocalRepoImp(requireContext())
            val tests = db.getChildById(id).childSolvedTests
            withContext(Dispatchers.Main){
                if(tests.isEmpty()){

                    binding.hint.visibility = View.VISIBLE
                    binding.recyclerView.visibility = View.GONE
                }
                else{
                    binding.hint.visibility = View.GONE
                    binding.recyclerView.visibility = View.VISIBLE
                    setTests(tests)
                }
            }

        }

    }

    override fun onTestClick(test: Test) {
        TODO("Not yet implemented")
    }

    override fun onDeleteClick(test: Test, position: Int) {
        TODO("Not yet implemented")
    }

    override fun onSolvedClick(test: SolvedTest, position: Int) {
        goToTheResult(test)
    }

    override fun onSolvedDelete(test: SolvedTest, position: Int) {
        DialogBuilder.showAlertDialog(requireContext(),
            "After deleting , you can do this exam again from toDo tests list?",
            "Delete Test",
            "Confirm",
            "Cancel",
            onConfirm = {
                lifecycleScope.launch(Dispatchers.IO) {
                    val db = LocalRepoImp(requireContext())
                    val child = db.getChildById(id)
                    val childSolvedTests = child.childSolvedTests as MutableList<SolvedTest>
                    childSolvedTests.remove(test)

                    db.updateSolvedTests(id, childSolvedTests)
                    withContext(Dispatchers.Main) {
                        Toast.makeText(requireContext(), "Moved to toDo", Toast.LENGTH_SHORT).show()
                        getDoneTests(id)
                        binding.recyclerView.adapter!!.notifyItemRemoved(position)
                        binding.recyclerView.adapter!!.notifyItemRangeChanged(position, childSolvedTests.size)
                    }
                }
            },
            onCancel = {

            })

    }
    private fun goToTheResult(solved:SolvedTest){
        val intent = Intent(requireContext(), TestResultActivity::class.java)
        intent.putExtra("testName",solved.testName)
        intent.putExtra("testType",solved.testType)
        intent.putExtra("q1r",solved.q1Points)
        intent.putExtra("q2r",solved.q2Points)
        intent.putExtra("q3r",solved.q3Points)
        intent.putExtra("q4r",solved.q4Points)
        intent.putExtra("childId",id)

        intent.putExtra("totalr",solved.totalPoints)
        intent.putExtra("date",solved.date)
        startActivity(intent)
    }
    override fun onResume() {
        super.onResume()
        getDoneTests(id)

    }

}