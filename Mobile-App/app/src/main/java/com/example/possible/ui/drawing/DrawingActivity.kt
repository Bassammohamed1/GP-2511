package com.example.possible.ui.drawing
import DialogBuilder
import android.os.Bundle
import android.view.View.GONE
import android.view.View.VISIBLE
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.example.possible.databinding.ActivityDrawingBinding
import com.example.possible.model.Child
import com.example.possible.repo.local.LettersAndNumbers
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.local.database.LocalRepoImp
import com.example.possible.util.helper.ChildTraker
import com.example.possible.util.helper.dataManager.AppDataManager
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

class DrawingActivity : AppCompatActivity() {
    private lateinit var binding: ActivityDrawingBinding
    private lateinit var fragment: DrawingFragment
    private lateinit var pref:SharedPref
    private var child : Child?=null
    private lateinit var viewModel: DrawingViewModel
    private var index=0
    private var type=""
    private lateinit var db: LocalRepoImp
    private var points = 100
    private var solved=false
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        pref=SharedPref(this)
        db = LocalRepoImp(this)
        viewModel = ViewModelProvider(this)[DrawingViewModel::class.java]
        binding = ActivityDrawingBinding.inflate(layoutInflater)
        //get the data from the previos
        index=intent.extras?.getInt("letterIndex",0)!!
        type=intent.extras?.getString("type",null)!!
        fragment = DrawingFragment().getInstance(index,type)
        setFrame(fragment)

        binding.backArrowIV.setOnClickListener{
            finish()
        }
        binding.doneButton.setOnClickListener {
            binding.loadingView.visibility= VISIBLE
                lifecycleScope.launch {
                    if(fragment.getResult()){
                        binding.celeprationView.visibility= VISIBLE
                        binding.celeprationAnim.playAnimation()
                        binding.doneButton.isEnabled=false
                        viewModel.updateWritingRate(this@DrawingActivity,pref,points,db,100)
                        solved = true
                    }
                    else{
                        DialogBuilder.showErrorDialog(this@DrawingActivity ,
                            "Wrong shape try again !"
                        ,"Try again")
                        decreasePoints()
                        fragment.reset()
                    }
                    binding.loadingView.visibility= GONE

                }

        }
        binding.nextBtn.setOnClickListener {
            handleNext()
            points = 100
            solved = false
        }


        setContentView(binding.root)

    }


    private fun handleNext(){
        if(type=="letter"){
            if(index!= LettersAndNumbers.letters.size-1){
                //go to next letter
                setNextData(index +1,"letter")
            }
            else{
                this.finish()
            }
        }
        else{
            if(index!= LettersAndNumbers.numbers.size-1){
                //go to next number
                    setNextData(index+1,"number")
            }
        }
    }
    private fun setNextData(index:Int, type:String){
        this.index=index
        this.type=type
        binding.nextBtn.isEnabled=false
        binding.nextBtn.postDelayed({
            binding.nextBtn.isEnabled=true}
            ,1000)
        binding.celeprationView.visibility= GONE
        binding.doneButton.isEnabled=true
        fragment= DrawingFragment().getInstance(index,type)
        setFrame(fragment)
    }

    private fun setFrame(fragment: Fragment){
        supportFragmentManager.beginTransaction()
            .replace(binding.frameDrawer.id,fragment)
            .commit()
    }

    override fun onResume() {
        super.onResume()
        AppDataManager.viewProfileImage(binding.profileIV,pref,this)
        val user=pref.getProfileDetails()
        binding.userNameTV.text=user.name
    }

    private fun decreasePoints(){
        var newPoints = points
        newPoints -= 10
        if (newPoints <=10) {
            newPoints = 10
        }
        points = newPoints
    }

    @OptIn(DelicateCoroutinesApi::class)
    override fun onDestroy() {
        super.onDestroy()
        if(!solved){
            //in the case of not solved
        GlobalScope.launch {
            child = db.getChildById(ChildTraker.getChildId())
            val latestSelecting = child!!.latestWritingDay
            val newWritingRate = child!!.writingRate
            db.updateWritingRate(ChildTraker.getChildId(), newWritingRate)
            //update the writing days and latest writing day
            if (ChildTraker.isAnotherDay(latestSelecting)) {
                db.updateWritingDays(ChildTraker.getChildId(), child!!.writingDays + 1)
                db.updateLatestWritingDay(ChildTraker.getChildId(), ChildTraker.getCurrentDate())
            }
        }
        }
    }



}