    package com.example.possible.ui.profile.children.testsForChildren

    import android.content.Intent
    import android.os.Bundle
    import androidx.fragment.app.Fragment
    import android.view.LayoutInflater
    import android.view.View
    import android.view.ViewGroup
    import androidx.lifecycle.lifecycleScope
    import com.example.possible.databinding.FragmentTestsToDoBinding
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

    class TestsToDoFragment : Fragment() , TestListener {
        private lateinit var binding: FragmentTestsToDoBinding
        private var id = 0
        fun newInstance(id:Int):TestsToDoFragment{
            val args = Bundle()
            args.putInt("id",id)
            val fragment = TestsToDoFragment()
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
        binding = FragmentTestsToDoBinding.inflate(inflater, container, false)
             id = arguments?.getInt("id")!!
        return binding.root
        }


        private fun setTests(tests: List<Test>) {
            val adapter = TestAdapter(tests as ArrayList<Test>,this)
            binding.recyclerView.adapter = adapter
            adapter.toDoMode()
        }

        private fun  getToDoTests(id:Int){
            val db = LocalRepoImp(requireContext())
            lifecycleScope.launch(Dispatchers.IO) {
                val tests = db.getChildById(id).childTests
                val solvedTests = db.getChildById(id).childSolvedTests
                val unSolvedTests = filterUnSolvedTests(tests,solvedTests)
                withContext(Dispatchers.Main){
                    if(unSolvedTests.isEmpty()){
                        binding.hint.visibility = View.VISIBLE
                        binding.recyclerView.visibility = View.GONE
                    }
                    else{
                        binding.hint.visibility = View.GONE
                        binding.recyclerView.visibility = View.VISIBLE
                        setTests(unSolvedTests)
                    }
                }

            }
        }

        private fun filterUnSolvedTests(tests: List<Test>, solvedTests: List<SolvedTest>): List<Test> {
            val unSolvedTests = mutableListOf<Test>()
               for(test in tests){
                   var isSolved = false
                   for(solvedTest in solvedTests) {
                       if (test.name == solvedTest.testName) {
                           isSolved = true
                           break
                       }
                   }
                   if(!isSolved){
                       unSolvedTests.add(test)
                   }
               }
            return unSolvedTests

        }




        override fun onTestClick(test: Test) {

            val intent = if (getCategory(test.name) == "BBB" || getCategory(test.name) == "CCC") {
                Intent(requireContext(), DysgraphiaTestActivity::class.java)
            } else {
                Intent(requireContext(), DyscalculiaTestActivity::class.java)
            }
            intent.putExtra("test", test.name)
            intent.putExtra("childId",id)
            startActivity(intent)
        }

        override fun onDeleteClick(test: Test, position: Int) {
        TODO("Not yet implemented")
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
        override fun onResume() {
            super.onResume()
            getToDoTests(id)
        }

    }