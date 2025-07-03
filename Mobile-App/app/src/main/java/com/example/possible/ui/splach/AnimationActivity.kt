package com.example.possible.ui.splach

import android.animation.ObjectAnimator
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.view.View
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.example.possible.R
import com.example.possible.databinding.ActivityAnimationBinding
import com.example.possible.repo.local.SharedPref
import com.example.possible.ui.MainActivity
import com.example.possible.ui.profile.children.Children
import com.example.possible.ui.specialist.SpecialistMainActivity

class AnimationActivity : AppCompatActivity() {
    private lateinit var binding: ActivityAnimationBinding
    private lateinit var handler: Handler
    private lateinit var pref: SharedPref

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        pref = SharedPref(this)
        binding = ActivityAnimationBinding.inflate(layoutInflater)
        handler = Handler()
        setContentView(binding.root)
        binding.smallRocket.animate().scaleX(0f).scaleY(0f).setDuration(1000).start()
        hideAnimation(binding.smallRocket,2000)
        hideAnimation(binding.rideRocket,2500)
        hideAnimation(binding.title,3000)
        animate()
        handler.postDelayed({
            goToMain()
        },6500)


    }

    private fun animate(){
        handler.postDelayed({
            val animator = ObjectAnimator.ofFloat(binding.rocket, "translationY", 0f, -5000f)
            animator.duration = 3000 // مدة الحركة (2 ثانية)
            animator.start()
        },4500)

    }
    private fun hideAnimation(view: View,delay:Long){
        handler.postDelayed({
            view.animate().scaleX(0f).scaleY(0f).setDuration(1500).withEndAction{
                view.visibility= View.GONE
            }.start()
        },delay)
    }

    private fun goToMain(){
        if(pref.getRole()=="User"){
            val intent = Intent(this, Children::class.java)
            intent.putExtra("mode", "select")
            startActivity(intent)
        }
        else if(pref.getRole()=="Specialist"){
            startActivity(Intent(this, SpecialistMainActivity::class.java))
        }
        finish()

    }
}