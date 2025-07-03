package com.example.possible.ui.signLogin.Login

import DialogBuilder
import android.content.Intent
import android.os.Bundle
import android.view.View.GONE
import android.view.View.VISIBLE
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import com.example.possible.databinding.ActivityLoginBinding
import com.example.possible.repo.local.SharedPref
import com.example.possible.ui.profile.children.Children
import com.example.possible.ui.signLogin.signUp.SignupActivity
import com.example.possible.ui.specialist.SpecialistMainActivity

class LoginActivity : AppCompatActivity() {
    private lateinit var  binding : ActivityLoginBinding
    private lateinit var viewModel: LoginViewModel
    private lateinit var pref: SharedPref
    lateinit var email: String
    lateinit var password: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)
        pref = SharedPref(this)
        viewModel = ViewModelProvider(this)[LoginViewModel::class.java]
        setControllers()
        DialogBuilder.ipDialog(this){
            pref.setIp(it)
        }

    }
    private fun setPathOfApp(path:String){
        pref.setRole(path)
        hideTheChoosingViewAndViewTheLoginView()
    }
    private fun hideTheChoosingViewAndViewTheLoginView(){
        try {
            binding.loginView.visibility = VISIBLE
        } catch (e: Exception) {
            TODO("Not yet implemented")
        }
        binding.loginView.animate().scaleX(0f).scaleY(0f).setDuration(0).start()
        binding.chooseParentOrSpecialist.animate().scaleX(0f).scaleY(0f).setDuration(300).withEndAction{
            binding.loginView.animate().scaleX(1f).scaleY(1f).setDuration(300).start()
            binding.chooseParentOrSpecialist.visibility = GONE
        }.start()
    }
    private fun setControllers() {
        binding.signup.setOnClickListener {
            startActivity(Intent(this, SignupActivity::class.java))
        }
        binding.loginBtn.setOnClickListener {
            email = binding.emailET.text.toString()
            password = binding.passwordET.text.toString()
            resultFromApi()
        }
        binding.chooseParentBtn.setOnClickListener {
            setPathOfApp("User")

        }
        binding.chooseSpecialistBtn.setOnClickListener {
            setPathOfApp("Specialist")
        }
    }

    private fun resultFromApi(){
        viewModel.loginUserSync(email = email, password = password, bind = binding, context = this){
            goToMainActivity()
            finish()
        }
    }

    private fun goToMainActivity() {
        if (pref.getRole() == "User") {
            val intent = Intent(this, Children::class.java)
            intent.putExtra("mode", "select")
            startActivity(intent)
        } else if (pref.getRole() == "Specialist") {
            startActivity(Intent(this, SpecialistMainActivity::class.java))
        }


    }}