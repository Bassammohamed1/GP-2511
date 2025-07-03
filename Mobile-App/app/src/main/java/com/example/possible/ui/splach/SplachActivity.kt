package com.example.possible.ui.splach

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.view.View
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import com.example.possible.databinding.ActivitySplachBinding
import com.example.possible.repo.local.SharedPref
import com.example.possible.ui.MainActivity
import com.example.possible.ui.profile.children.Children
import com.example.possible.ui.signLogin.Login.LoginActivity
import com.example.possible.ui.specialist.SpecialistMainActivity

class SplachActivity : AppCompatActivity(){
    private lateinit var binding: ActivitySplachBinding
    private var dir = -1
      private lateinit var p: View

      private lateinit var o: View

      private lateinit var s: View

      private lateinit var s2: View

      private lateinit var i: View

      private lateinit var b: View

      private lateinit var l: View

      private lateinit var e: View

      private lateinit var brain: View
      private lateinit var pref: SharedPref

    private lateinit var handler: Handler
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        handler = Handler()
        binding = ActivitySplachBinding.inflate(layoutInflater)
        setContentView(binding.root)
        pref = SharedPref(this)

        p=binding.p
        o=binding.o
        s=binding.s
        s2=binding.s2
        i=binding.i
        b=binding.b
        l=binding.l
        e=binding.e
        brain = binding.brainImg

        hideWord()
        handler.postDelayed({
            animateText()
            animateView()
        },800)

        handler.postDelayed({
            if(isLogin()){
                goToMainActivity()
            }
            else{
                goToLoginActivity()
            }
        },3000)
    }

    private fun animateText() {
        animateLetter(p, 1, 200)
        animateLetter(o, 2,200 )
        animateLetter(s, 3, 200)
        animateLetter(s2, 4, 200)
        animateLetter(i, 5,200 )
        animateLetter(b, 4,200 )
        animateLetter(l, 3, 200)
        animateLetter(e, 2, 200)
        animateLetter(brain, 1, 200)
    }
    private fun animateView(){
        binding.titleShow.animate().scaleX(.8f).scaleY(.8f).setDuration(1000)
            .withEndAction{
                binding.titleShow.animate().scaleX(1f).scaleY(1f).setDuration(1000).start()
            }.start()
    }
    private fun animateLetter(view: View, times: Int, delay: Long) {
        dir *= -1 // تغيير الاتجاه كل مرة
        fun startAnimation(count: Int) {
            val valueOfTrans =delay * dir .toFloat()

            if (count < times) {
                view.animate().alpha(1f).setDuration(delay).translationX(-valueOfTrans*-1).translationY(valueOfTrans).withEndAction {
                    view.animate().alpha(0f).setDuration(delay/5).translationX(1f).translationY(1f).withEndAction {
                        startAnimation(count + 1) // استدعاء الأنيميشن مرة أخرى حتى ينتهي العدد المطلوب
                    }.start()
                }.start()
            } else {
                view.animate().alpha(1f).setDuration(delay).start() // التأكد أن الـ View يظهر بعد انتهاء التكرار
            }
        }

        //dir *= -1 // تغيير الاتجاه كل مرة
        startAnimation(0) // تشغيل الأنيميشن أول مرة
    }

    private fun hideWord(){
        p.animate().alpha(0f).setDuration(800).start()
        o.animate().alpha(0f).setDuration(600).start()
        s.animate().alpha(0f).setDuration(700).start()
        s2.animate().alpha(0f).setDuration(700).start()
        i.animate().alpha(0f).setDuration(700).start()
        b.animate().alpha(0f).setDuration(600).start()
        l.animate().alpha(0f).setDuration(800).start()
        e.animate().alpha(0f).setDuration(800).start()
        brain.animate().alpha(0f).setDuration(800).start()

    }
    private fun goToMainActivity() {
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
    private fun goToLoginActivity() {
        val intent = Intent(this, LoginActivity::class.java)
        startActivity(intent)
        finish()
    }
    private fun isLogin():Boolean{
        return (pref.getToken()!!.isNotEmpty())
    }



}