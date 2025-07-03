package com.example.possible.ui.signLogin.Login

import android.content.Context
import android.view.View.GONE
import android.view.View.VISIBLE
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.possible.databinding.ActivityEditProfileBinding
import com.example.possible.databinding.ActivityLoginBinding
import com.example.possible.model.LoginBody
import com.example.possible.repo.local.SharedPref
import com.example.possible.repo.remote.RetrofitBuilder
import com.example.possible.util.LogoutHandler
import com.example.possible.util.helper.dataManager.AppDataManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class LoginViewModel : ViewModel() {

    fun loginUserSync(
        email: String,
        password: String,
        bind: ActivityLoginBinding,
        context: Context,
        onLoginSuccess: () -> Unit
    ) {
        val p =SharedPref(context)
        viewModelScope.launch(Dispatchers.IO) {
            withContext(Dispatchers.Main){
                bind.loadingView.visibility = VISIBLE
            }
            try {
                val loginBody = LoginBody(email, password)

                val response = RetrofitBuilder.loginApiService
                    .login(loginBody)

                withContext(Dispatchers.Main) {
                    if (response.isSuccessful) {
                        val registerResponse = response.body()!!
                        val username = registerResponse.userName
                        val image = registerResponse.image
                        val token = registerResponse.token
                        val userId = registerResponse.userId
                        val expiration = registerResponse.expiration
                        val role = registerResponse.roles[0]
                        p.setToken(token)
                        AppDataManager.saveProfileData(
                            context,
                            SharedPref(context),
                            image,
                            username,
                            email,
                            password,
                            expiration,
                            token,
                            userId,
                            role
                        )
                        delay(1000)
                        Toast.makeText(context, "✅ Login Success!", Toast.LENGTH_SHORT).show()
                        onLoginSuccess()
                        LogoutHandler.isLoggingOUt=false

                    } else {
                        val errorBody = response.errorBody()?.string()
                        errorBody?.let {
                            val jsonObject = JSONObject(it)
                            if (jsonObject.has("errors")) {
                                val errors = jsonObject.getJSONObject("errors")
                                if (errors.has("Email")) {
                                    val emailErrors = "❌ invalid email: " + errors.getJSONArray("Email").getString(0)
                                    withContext(Dispatchers.Main) {
                                        bind.emailLayout.error = emailErrors
                                    }

                                }
                                if (errors.has("Password")) {
                                    val passwordErrors = "❌ invalid password: " + errors.getJSONArray("Password").getString(0)
                                    withContext(Dispatchers.Main) {
                                        bind.passLayout.error = passwordErrors
                                    }
                                }
                            } else if (jsonObject.has("Custom")) {
                                val customErrors = jsonObject.getJSONArray("Custom")
                                val errorMessage = customErrors.getString(0)
                                if (errorMessage.split(" ")[0]=="Passwords")  {
                                    withContext(Dispatchers.Main) {
                                        bind.passLayout.error = errorMessage
                                    }
                                }
                                else {
                                    withContext(Dispatchers.Main) {
                                        Toast.makeText(context,errorMessage, Toast.LENGTH_LONG).show()
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(context, "❌ Network Error: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
            withContext(Dispatchers.Main){
                bind.loadingView.visibility = GONE
            }
        }

    } fun loginBehindUpdate(email: String, password: String, context: Context,bind: ActivityEditProfileBinding){
        viewModelScope.launch(Dispatchers.IO) {
            withContext(Dispatchers.Main){
                bind.loadingView.visibility = VISIBLE
            }
            //try {
                val loginBody = LoginBody(email, password)

                val response = RetrofitBuilder.loginApiService
                    .login(loginBody)
                if (response.isSuccessful) {
                    val registerResponse = response.body()!!
                    withContext(Dispatchers.Main) {
                    Toast.makeText(context, "✅Info Updated!", Toast.LENGTH_SHORT).show()}
                    val pref = SharedPref(context)
                    val name =registerResponse.userName
                    val image =registerResponse.image
                    val role =registerResponse.roles[0]


                    AppDataManager.saveProfileData(
                        context,
                        pref,
                        image,
                        name,
                        email,
                        password,
                        registerResponse.expiration,
                        registerResponse.token,
                        registerResponse.userId,
                        role
                    )
                    delay(1000)
                    withContext(Dispatchers.Main){
                    bind.loadingView.visibility = GONE}

                } else {
                    Toast.makeText(
                        context,
                        "Try again later , click edit profile again and check your internet connection",
                        Toast.LENGTH_LONG
                    ).show()
              //  }
           /* }catch (e: Exception){
                withContext(Dispatchers.Main) {
                    Toast.makeText(context, "❌ Network Error: ${e.message}", Toast.LENGTH_SHORT).show()
                }*/
            }


        }

    }
}
