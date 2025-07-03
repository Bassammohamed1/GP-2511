package com.example.possible.ui

import android.content.Intent
import android.graphics.Rect
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.possible.model.Letter
import com.example.possible.util.adapter.LettersAdapter
import com.example.possible.repo.local.LettersAndNumbers
import com.example.possible.databinding.ActivityLettersNumbersBinding
import com.example.possible.repo.local.SharedPref
import com.example.possible.ui.drawing.DrawingActivity
import com.example.possible.ui.tracing.TracingActivity
import com.example.possible.util.TestDecoder
import com.example.possible.util.helper.dataManager.AppDataManager
import com.example.possible.util.listener.LettersListener

class LettersNumbersActivity : AppCompatActivity() , LettersListener {
    private lateinit var binding: ActivityLettersNumbersBinding
    private lateinit var list: List<Letter>
    private lateinit var title: String
    private lateinit var pref: SharedPref
    private var numOfQuestion=0
    private var level = ""
    private var index=0
    private var type=""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        if (intent.extras?.getString("result")=="letters"){
            list= LettersAndNumbers.letters
             title="Letters"
        }else{
            list= LettersAndNumbers.numbers
            title="Numbers"
        }
        binding = ActivityLettersNumbersBinding.inflate(layoutInflater)
        pref = SharedPref(this)


        binding.title.text=title
        val recyclerView=binding.recycler
        val gridLayoutManager = GridLayoutManager(this, 2) // Number of columns
        recyclerView.layoutManager = gridLayoutManager

// Add item spacing decoration to align items properly
       recyclerView.addItemDecoration(object : RecyclerView.ItemDecoration() {
            override fun getItemOffsets(
                outRect: Rect,
                view: View,
                parent: RecyclerView,
                state: RecyclerView.State
            ) {
                parent.getChildAdapterPosition(view)
                gridLayoutManager.spanCount
                state.itemCount

                // Apply equal padding around items to center-align them
                val spacing = 50 // Adjust as needed
                outRect.left = spacing / 2
                outRect.right = spacing / 2
                outRect.top = spacing / 2
                outRect.bottom = spacing / 2
            }
        })
        recyclerView.adapter = LettersAdapter(list,this)



        binding.backArrowIV.setOnClickListener{
            this.finish()
        }

        setContentView(binding.root)
    }

    override fun onClick(letter: Letter, position: Int) {
        if(isItFromSettingTest()){
            index=position
            getTheQuestionOnDone(numOfQuestion)
            Toast.makeText(this, "Question is done", Toast.LENGTH_SHORT).show()
            finish()
        }
        else{
        val intent1 = Intent(this, TracingActivity::class.java)
        intent1.putExtra("letterIndex",position)
        intent1.putExtra("type",letter.type)
        val intent = Intent(this, DrawingActivity::class.java)
        intent.putExtra("letterIndex", position)
        intent.putExtra("type",letter.type)
        if(pref.getMode()=="beginner")
            startActivity(intent1)
        else
            startActivity(intent)
    }
    }
   /* private fun loadProfileImage() {
        val savedUri = pref.getImage()
        if (savedUri != null) {
            val uri = Uri.parse(savedUri)
            binding.profileIV.setImageURI(uri)
        }}*/

    override fun onResume() {
        super.onResume()
        AppDataManager.viewProfileImage(binding.profileIV,pref,this)
        val userName=pref.getProfileDetails().name
        binding.userNameTV.text=userName
    }
    private fun isItFromSettingTest():Boolean{
        numOfQuestion = intent.getIntExtra("noOfQuestion",0)
        type = intent.getStringExtra("type")?:""
        level = intent.getStringExtra("level")?:""
        return numOfQuestion!=0

    }
    private fun getTheQuestionOnDone(numOfQuestion:Int){
        val ques = TestDecoder.encodeLetterOrNumber(index,type,level)
        setWhichQuestion(ques,numOfQuestion)
    }
    private fun setWhichQuestion(ques:String,numOfQuestion:Int){
        when(numOfQuestion){
            1->{
                pref.setQ1(ques)
            }
            2->{
                pref.setQ2(ques)
            }
            3->{
                pref.setQ3(ques)
            }
            4->{
                pref.setQ4(ques)
            }
        }
    }
}